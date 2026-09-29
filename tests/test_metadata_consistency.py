"""Controlled synthetic test for A7."""
import tempfile
from pathlib import Path

from PIL import Image

from backend.engines.dataset.metadata_consistency import (
    assess_metadata_consistency,
)


def _save(
    path: Path,
    size,
    camera=None,
    quality=90,
    fmt="JPEG",
    color=(120, 80, 40),
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    image = Image.new(
        "RGB",
        size,
        color,
    )

    kwargs = {}

    if camera:
        exif = Image.Exif()
        exif[0x0110] = camera
        kwargs["exif"] = exif

    if fmt == "JPEG":
        kwargs["quality"] = quality

    image.save(
        path,
        fmt,
        **kwargs,
    )


def build_dataset(root: Path) -> dict[str, str]:
    contributor_map = {}

    for i in range(8):
        filename = f"alice_{i}.jpg"

        _save(
            root / filename,
            (64, 64),
            "CamA",
        )

        contributor_map[filename] = "alice"

    for i in range(8):
        filename = f"carol_{i}.jpg"

        _save(
            root / filename,
            (64, 64),
            "CamA",
        )

        contributor_map[filename] = "carol"

    _save(
        root / "carol_fake.jpg",
        (64, 64),
        fmt="PNG",
    )

    contributor_map["carol_fake.jpg"] = "carol"

    for i in range(4):
        filename = f"bob_{i}.jpg"

        _save(
            root / filename,
            (128, 96),
            None,
            quality=60,
        )

        contributor_map[filename] = "bob"

    (root / "broken.jpg").write_bytes(
        b"not an image"
    )

    return contributor_map


def test_a7_flags_divergent_contributor_and_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        contributor_map = build_dataset(root)

        result_1 = assess_metadata_consistency(
            root,
            contributor_map=contributor_map,
        )

        result_2 = assess_metadata_consistency(
            root,
            contributor_map=contributor_map,
        )

    assert result_1 == result_2
    assert result_1["status"] == "completed"
    assert result_1["image_count"] == 21

    assert [
        item["file"]
        for item in result_1["skipped_files"]
    ] == ["broken.jpg"]

    flagged = {
        item["contributor"]
        for item in result_1["contributor_findings"]
    }

    assert flagged == {"bob"}

    bob_attributes = {
        item["attribute"]
        for item in result_1["contributor_findings"]
    }

    assert {
        "resolution",
        "camera",
        "has_exif",
        "quant_hash",
    } <= bob_attributes

    image_codes = {
        (item["file"], item["code"])
        for item in result_1["image_findings"]
    }

    assert (
        "carol_fake.jpg",
        "format_extension_mismatch",
    ) in image_codes

    assert "contributor_evidence" in result_1
    assert "limitations" in result_1


def test_a7_invalid_directory():
    result = assess_metadata_consistency(
        "/nonexistent/path/xyz"
    )

    assert result["status"] == "error"


if __name__ == "__main__":
    test_a7_flags_divergent_contributor_and_mismatch()
    test_a7_invalid_directory()

    print("A7 tests passed")
