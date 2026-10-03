"""Standalone tests for TRACER-CV B4 Trigger Search.

Run:
    python -m tests.test_trigger_search
"""

from __future__ import annotations

import sys

import numpy as np

from backend.engines.model import trigger_search as b4


def check(condition, message="check failed"):
    if not condition:
        raise AssertionError(message)


class SyntheticTriggerAdapter(b4.ClassificationAdapter):
    """Tiny deterministic model with a known bottom-right white trigger.

    Class 0 is the normal class.
    A sufficiently bright bottom-right patch produces class 1.
    """

    output_type = "logits"

    def predict(self, images):
        outputs = []

        for image in images:
            arr = np.asarray(image)

            h, w = arr.shape[:2]

            region = arr[
                int(h * 0.70):h,
                int(w * 0.70):w,
            ]

            brightness = float(np.mean(region))

            if brightness > 150.0:
                outputs.append([0.05, 8.0])
            else:
                outputs.append([5.0, 0.2])

        return np.asarray(outputs, dtype=np.float32)


def make_images(count=6, seed=123):
    rng = np.random.RandomState(seed)
    return [
        rng.randint(20, 80, size=(32, 32, 3), dtype=np.uint8)
        for _ in range(count)
    ]


def test_01_config_validation():
    cfg = b4.TriggerSearchConfig()
    cfg.validate()
    check(cfg.patch_sizes)
    check(cfg.patterns)


def test_02_candidate_generation_deterministic():
    cfg = b4.TriggerSearchConfig(
        patch_sizes=(8,),
        grid_fractions=(0.25, 0.75),
        patterns=("white", "black"),
    )

    a = b4.generate_candidates((32, 32, 3), cfg)
    c = b4.generate_candidates((32, 32, 3), cfg)

    check(a == c)
    check(len(a) == 8)


def test_03_trigger_application_deterministic():
    image = np.zeros((16, 16, 3), dtype=np.uint8)

    candidate = b4.CandidateSpec(
        patch_size=4,
        x_fraction=1.0,
        y_fraction=1.0,
        pattern="white",
    )

    a = b4.apply_trigger(image, candidate)
    c = b4.apply_trigger(image, candidate)

    check(np.array_equal(a, c))
    check(np.all(a[-4:, -4:] == 255))
    check(np.all(a[:-4, :] == 0))


def test_04_patterns():
    image = np.full((16, 16, 3), 100, dtype=np.uint8)

    for pattern in ("black", "white", "mean", "checkerboard"):
        candidate = b4.CandidateSpec(
            patch_size=4,
            x_fraction=0.5,
            y_fraction=0.5,
            pattern=pattern,
        )

        output = b4.apply_trigger(image, candidate)

        check(output.shape == image.shape)
        check(output.dtype == np.uint8)


def test_05_callable_adapter():
    adapter = b4.CallableClassificationAdapter(
        lambda images: np.tile(np.asarray([[1.0, 0.0]]), (len(images), 1)),
        output_type="logits",
    )

    probs = b4._predict_probabilities(adapter, make_images(2))

    check(probs.shape == (2, 2))
    check(np.allclose(np.sum(probs, axis=1), 1.0))


def test_06_probability_adapter():
    adapter = b4.CallableClassificationAdapter(
        lambda images: np.tile(np.asarray([[0.25, 0.75]]), (len(images), 1)),
        output_type="probabilities",
    )

    probs = b4._predict_probabilities(adapter, make_images(2))

    check(np.allclose(probs[:, 0], 0.25))
    check(np.allclose(probs[:, 1], 0.75))


def test_07_stable_softmax():
    logits = np.asarray([[1000.0, 999.0]], dtype=np.float64)
    probs = b4._stable_softmax(logits)

    check(np.all(np.isfinite(probs)))
    check(np.allclose(np.sum(probs), 1.0))
    check(probs[0, 0] > probs[0, 1])


def test_08_known_trigger_detected():
    images = make_images()

    cfg = b4.TriggerSearchConfig(
        patch_sizes=(8,),
        grid_fractions=(0.25, 0.5, 0.75, 1.0),
        patterns=("white", "black"),
        min_prediction_change_rate=0.60,
        min_confidence_gain=0.005,
        min_samples=3,
        max_images=6,
    )

    result = b4.search_triggers(
        images,
        SyntheticTriggerAdapter(),
        config=cfg,
        model_id="sha256:" + "a" * 64,
    )

    check(result["status"] == "completed")
    check(result["candidate_trigger_count"] >= 1, result)
    check(
        result["assessment"]["status"]
        == "candidate_trigger_like_behavior"
    )

    evidence = result["candidate_evidence"][0]

    check(evidence["candidate"]["pattern"] == "white")
    check(evidence["class_change_rate"] >= 0.60)
    check(evidence["mean_confidence_gain"] >= 0.005)
    check(evidence["candidate_trigger_like"] is True)


def test_09_model_id_bound_to_evidence():
    result = b4.search_triggers(
        make_images(3),
        SyntheticTriggerAdapter(),
        config=b4.TriggerSearchConfig(
            patch_sizes=(8,),
            grid_fractions=(0.5,),
            patterns=("white",),
        ),
        model_id="sha256:" + "b" * 64,
    )

    check(result["model"]["model_id"] == "sha256:" + "b" * 64)


def test_10_no_candidate_clean_model():
    class StableAdapter(b4.ClassificationAdapter):
        output_type = "logits"

        def predict(self, images):
            return np.tile(
                np.asarray([[6.0, 0.1]], dtype=np.float32),
                (len(images), 1),
            )

    result = b4.search_triggers(
        make_images(),
        StableAdapter(),
        config=b4.TriggerSearchConfig(
            patch_sizes=(8,),
            grid_fractions=(0.5,),
            patterns=("black", "white", "mean"),
        ),
    )

    check(result["status"] == "completed")
    check(result["candidate_trigger_count"] == 0)
    check(
        result["assessment"]["status"]
        == "no_candidate_trigger_like_behavior"
    )


def test_11_invalid_images():
    result = b4.search_triggers(
        [np.zeros((8, 8), dtype=np.uint8)],
        SyntheticTriggerAdapter(),
    )

    check(result["status"] == "unavailable")
    check(result["error"]["code"] == "invalid_images")


def test_12_empty_images():
    result = b4.search_triggers(
        [],
        SyntheticTriggerAdapter(),
    )

    check(result["status"] == "unavailable")
    check(result["error"]["code"] == "empty_images")


def test_13_adapter_error():
    class BrokenAdapter(b4.ClassificationAdapter):
        output_type = "logits"

        def predict(self, images):
            raise RuntimeError("synthetic failure")

    result = b4.search_triggers(
        make_images(),
        BrokenAdapter(),
    )

    check(result["status"] == "unavailable")
    check(result["error"]["code"] == "prediction_error")


def test_14_prediction_count_mismatch():
    class BadAdapter(b4.ClassificationAdapter):
        output_type = "logits"

        def predict(self, images):
            return np.asarray([[1.0, 2.0]], dtype=np.float32)

    result = b4.search_triggers(
        make_images(3),
        BadAdapter(),
    )

    check(result["status"] == "unavailable")
    check(result["error"]["code"] == "prediction_count_mismatch")


def test_15_no_timestamps():
    result = b4.search_triggers(
        make_images(3),
        SyntheticTriggerAdapter(),
        config=b4.TriggerSearchConfig(
            patch_sizes=(8,),
            grid_fractions=(0.5,),
            patterns=("white",),
        ),
    )

    def walk(value, path=""):
        found = []

        if isinstance(value, dict):
            for key, item in value.items():
                p = f"{path}.{key}" if path else str(key)

                if any(
                    token in str(key).lower()
                    for token in ("timestamp", "datetime", "created", "generated")
                ):
                    found.append(p)

                found.extend(walk(item, p))

        elif isinstance(value, list):
            for index, item in enumerate(value):
                found.extend(walk(item, f"{path}[{index}]"))

        return found

    check(not walk(result))


def test_16_invalid_config():
    try:
        b4.TriggerSearchConfig(
            min_prediction_change_rate=2.0
        ).validate()
    except ValueError:
        pass
    else:
        raise AssertionError("invalid config accepted")


def test_17_deterministic_result():
    images = make_images()

    cfg = b4.TriggerSearchConfig(
        patch_sizes=(8,),
        grid_fractions=(0.5, 0.75),
        patterns=("white", "black"),
    )

    adapter = SyntheticTriggerAdapter()

    a = b4.search_triggers(images, adapter, config=cfg)
    c = b4.search_triggers(images, adapter, config=cfg)

    check(a == c)


def test_18_unavailable_helper():
    result = b4.build_unavailable_report(
        "black_box",
        "Prediction interface unavailable.",
        model_id="sha256:" + "c" * 64,
    )

    check(result["status"] == "unavailable")
    check(result["error"]["code"] == "black_box")
    check(result["model"]["model_id"] == "sha256:" + "c" * 64)


def test_19_torch_adapter_present():
    try:
        import torch
    except ImportError:
        return

    class TinyModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.flatten = torch.nn.Flatten()
            self.fc = torch.nn.Linear(3 * 8 * 8, 2)

        def forward(self, x):
            return self.fc(self.flatten(x))

    model = TinyModel()

    adapter = b4.TorchClassificationAdapter(
        model,
        device="cpu",
    )

    images = [
        np.zeros((8, 8, 3), dtype=np.uint8),
        np.ones((8, 8, 3), dtype=np.uint8) * 255,
    ]

    output = adapter.predict(images)

    check(output.shape == (2, 2))
    check(np.all(np.isfinite(output)))


def main():
    tests = sorted(
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    )

    passed = 0
    failed = 0

    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except Exception as exc:
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
            failed += 1

    print(
        f"Ran {len(tests)} tests: "
        f"{passed} passed, {failed} failed"
    )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
