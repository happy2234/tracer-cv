from __future__ import annotations

from itertools import combinations
from pathlib import Path

from PIL import Image, UnidentifiedImageError


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".tif",
    ".tiff",
    ".webp",
}


def dhash(image_path: Path) -> int:
    """
    Generate a 64-bit difference hash (dHash).

    The image is converted to grayscale and resized to 9x8.
    Each horizontal pixel pair produces one comparison bit.
    """

    with Image.open(image_path) as image:
        image = image.convert("L")
        image = image.resize((9, 8))

        pixels = list(image.getdata())

    hash_value = 0

    for row in range(8):
        offset = row * 9

        for column in range(8):
            left = pixels[offset + column]
            right = pixels[offset + column + 1]

            hash_value <<= 1

            if left > right:
                hash_value |= 1

    return hash_value


def hamming_distance(left: int, right: int) -> int:
    """Return the number of differing bits between two hashes."""
    return (left ^ right).bit_count()


def discover_images(dataset_dir: Path) -> list[Path]:
    """Find supported image files recursively."""

    images = []

    for path in sorted(dataset_dir.rglob("*")):
        if not path.is_file():
            continue

        if path.suffix.lower() in IMAGE_EXTENSIONS:
            images.append(path)

    return images


def find_near_duplicates(
    dataset_dir: Path,
    threshold: int = 8,
) -> dict:
    """
    Detect visually similar images using dHash Hamming distance.

    Lower distance means greater perceptual similarity.

    threshold:
        Maximum Hamming distance considered a near-duplicate.
    """

    dataset_dir = dataset_dir.resolve()

    if not dataset_dir.is_dir():
        raise ValueError(
            f"Dataset directory does not exist: {dataset_dir}"
        )

    image_paths = discover_images(dataset_dir)

    hashes = []
    skipped_files = []

    for image_path in image_paths:
        try:
            image_hash = dhash(image_path)

            hashes.append(
                {
                    "path": image_path.relative_to(dataset_dir).as_posix(),
                    "hash": image_hash,
                }
            )

        except (UnidentifiedImageError, OSError, ValueError):
            skipped_files.append(
                image_path.relative_to(dataset_dir).as_posix()
            )

    matches = []

    for left, right in combinations(hashes, 2):
        distance = hamming_distance(
            left["hash"],
            right["hash"],
        )

        if distance <= threshold:
            matches.append(
                {
                    "file_a": left["path"],
                    "file_b": right["path"],
                    "hamming_distance": distance,
                    "threshold": threshold,
                }
            )

    return {
        "status": "completed",
        "method": "dHash",
        "threshold": threshold,
        "images_discovered": len(image_paths),
        "images_hashed": len(hashes),
        "skipped_files": skipped_files,
        "near_duplicate_pair_count": len(matches),
        "pairs": matches,
    }
