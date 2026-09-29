from collections import defaultdict


def find_exact_duplicates(files: list[dict]) -> dict:
    """
    Find exact duplicate files using their SHA-256 hashes.

    Files with the same SHA-256 are grouped together.
    Groups containing only one file are not duplicates.
    """

    hash_groups = defaultdict(list)

    for file_info in files:
        hash_groups[file_info["sha256"]].append(
            file_info["path"]
        )

    duplicate_groups = []

    for file_hash, paths in sorted(hash_groups.items()):
        if len(paths) > 1:
            duplicate_groups.append(
                {
                    "sha256": file_hash,
                    "files": sorted(paths),
                    "count": len(paths),
                }
            )

    duplicate_file_count = sum(
        group["count"]
        for group in duplicate_groups
    )

    return {
        "status": "completed",
        "duplicate_group_count": len(duplicate_groups),
        "duplicate_file_count": duplicate_file_count,
        "groups": duplicate_groups,
    }
