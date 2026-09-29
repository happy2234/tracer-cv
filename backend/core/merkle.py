from __future__ import annotations

from hashlib import sha256
from typing import Iterable


def _hash_pair(left: str, right: str) -> str:
    data = f"{left}{right}".encode("utf-8")
    return sha256(data).hexdigest()


def merkle_root(leaves: Iterable[str]) -> str:
    nodes = list(leaves)

    if not nodes:
        return sha256(b"").hexdigest()

    nodes = sorted(nodes)

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        nodes = [
            _hash_pair(nodes[i], nodes[i + 1])
            for i in range(0, len(nodes), 2)
        ]

    return nodes[0]
