"""
TRACER-CV C2 — Distribution Shift tests.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image

from backend.engines.shift.distribution_shift import (
    DistributionShiftConfig,
    analyze_distribution_shift,
)


PASSED = 0
FAILED = 0


def check(name: str, condition: bool) -> None:
    global PASSED, FAILED

    if condition:
        print(f"PASS {name}")
        PASSED += 1
    else:
        print(f"FAIL {name}")
        FAILED += 1


def make_image(
    path: Path,
    value: int,
    *,
    pattern: bool = False,
) -> None:

    if pattern:
        arr = np.zeros(
            (64, 64, 3),
            dtype=np.uint8,
        )

        arr[:, ::2] = value
        arr[:, 1::2] = 255 - value

    else:
        arr = np.full(
            (64, 64, 3),
            value,
            dtype=np.uint8,
        )

    Image.fromarray(arr, "RGB").save(path)


def build_fixture(root: Path) -> tuple[Path, Path]:
    reference = root / "reference"
    candidate = root / "candidate"

    reference.mkdir()
    candidate.mkdir()

    # Reference population:
    # moderate brightness with varied values.
    for index, value in enumerate(
        [80, 90, 100, 110, 120, 130]
    ):
        make_image(
            reference / f"ref_{index}.png",
            value,
        )

    # Candidate population with strong brightness shift.
    for index, value in enumerate(
        [220, 225, 230, 235, 240, 245]
    ):
        make_image(
            candidate / f"candidate_{index}.png",
            value,
        )

    return reference, candidate


def test_shift_detection() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference, candidate = build_fixture(root)

        result = analyze_distribution_shift(
            [reference],
            [candidate],
        )

        check(
            "01 analysis completed",
            result["status"] == "completed",
        )

        check(
            "02 reference images loaded",
            result["reference"]["image_count"] == 6,
        )

        check(
            "03 candidate images loaded",
            result["candidate"]["image_count"] == 6,
        )

        check(
            "04 brightness distance detected",
            result["distances"]["scalar"]["brightness"] > 0.20,
        )

        check(
            "05 brightness marked shifted",
            any(
                item["feature"] == "brightness"
                and item["shifted"]
                for item in result["shifted_features"]
            ),
        )

        check(
            "06 overall shift detected",
            result["overall_shift"] > 0.20,
        )

        check(
            "07 finding generated",
            len(result["findings"]) >= 1,
        )

        check(
            "08 result digest generated",
            len(result["result_digest"]) == 64,
        )


def test_no_shift() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference = root / "reference"
        candidate = root / "candidate"

        reference.mkdir()
        candidate.mkdir()

        values = [80, 90, 100, 110, 120, 130]

        for index, value in enumerate(values):
            make_image(
                reference / f"ref_{index}.png",
                value,
            )

            make_image(
                candidate / f"candidate_{index}.png",
                value,
            )

        result = analyze_distribution_shift(
            [reference],
            [candidate],
        )

        check(
            "09 identical populations complete",
            result["status"] == "completed",
        )

        check(
            "10 identical populations low shift",
            result["overall_shift"] < 0.01,
        )

        check(
            "11 identical populations no severity",
            result["severity"] == "none",
        )


def test_edge_shift() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference = root / "reference"
        candidate = root / "candidate"

        reference.mkdir()
        candidate.mkdir()

        for index, value in enumerate(
            [100, 105, 110, 115, 120, 125]
        ):
            make_image(
                reference / f"ref_{index}.png",
                value,
            )

            make_image(
                candidate / f"candidate_{index}.png",
                value,
                pattern=True,
            )

        result = analyze_distribution_shift(
            [reference],
            [candidate],
        )

        check(
            "12 edge-shift analysis complete",
            result["status"] == "completed",
        )

        check(
            "13 edge density changed",
            result["distances"]["scalar"]["edge_density"] > 0.01,
        )


def test_invalid_reference() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference = root / "reference"
        candidate = root / "candidate"

        reference.mkdir()
        candidate.mkdir()

        (reference / "broken.txt").write_text(
            "not an image",
            encoding="utf-8",
        )

        make_image(
            candidate / "candidate.png",
            100,
        )

        result = analyze_distribution_shift(
            [reference],
            [candidate],
        )

        check(
            "14 invalid reference handled",
            result["status"] == "unavailable",
        )


def test_invalid_candidate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference = root / "reference"
        candidate = root / "candidate"

        reference.mkdir()
        candidate.mkdir()

        make_image(
            reference / "reference.png",
            100,
        )

        (candidate / "broken.txt").write_text(
            "not an image",
            encoding="utf-8",
        )

        result = analyze_distribution_shift(
            [reference],
            [candidate],
        )

        check(
            "15 invalid candidate handled",
            result["status"] == "unavailable",
        )


def test_deterministic() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference, candidate = build_fixture(root)

        config = DistributionShiftConfig(
            seed=1337,
        )

        result_a = analyze_distribution_shift(
            [reference],
            [candidate],
            config=config,
        )

        result_b = analyze_distribution_shift(
            [reference],
            [candidate],
            config=config,
        )

        check(
            "16 deterministic result digest",
            result_a["result_digest"]
            == result_b["result_digest"],
        )


def test_limit() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        reference = root / "reference"
        candidate = root / "candidate"

        reference.mkdir()
        candidate.mkdir()

        for index in range(10):
            make_image(
                reference / f"ref_{index}.png",
                100,
            )

            make_image(
                candidate / f"candidate_{index}.png",
                100,
            )

        result = analyze_distribution_shift(
            [reference],
            [candidate],
            config=DistributionShiftConfig(
                max_images=4,
            ),
        )

        check(
            "17 max image limit respected",
            result["reference"]["image_count"] == 4
            and result["candidate"]["image_count"] == 4,
        )


def main() -> int:
    global PASSED, FAILED

    print("=" * 72)
    print("TRACER-CV C2 — DISTRIBUTION SHIFT TESTS")
    print("=" * 72)

    test_shift_detection()
    test_no_shift()
    test_edge_shift()
    test_invalid_reference()
    test_invalid_candidate()
    test_deterministic()
    test_limit()

    print("\n" + "=" * 72)
    print(
        f"Ran {PASSED + FAILED} tests: "
        f"{PASSED} passed, {FAILED} failed"
    )
    print("=" * 72)

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
