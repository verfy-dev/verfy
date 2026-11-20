"""RFC 6962 Merkle trees: checking Verfy's transparency log offline.

Verfy Cloud adds every receipt it accepts as the next leaf of one append-only Merkle tree (a leaf is
SHA-256(0x00 || the receipt's 32-byte hash), a node SHA-256(0x01 || left || right)), and signs the tree's size and
root with its witness key. ``verify_inclusion`` checks that a receipt is in a tree with a given root (RFC 9162
2.1.3.2), so a signed tree head published earlier keeps Verfy from dropping or reordering a receipt it accepted.
"""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(_root(leaves[:k]), _root(leaves[k:]))


def tree_root(data: list[bytes]) -> bytes:
    if not data:
        return hashlib.sha256(b"").digest()
    return _root([leaf_hash(d) for d in data])


def inclusion_path(m: int, data: list[bytes]) -> list[bytes]:
    if not 0 <= m < len(data):
        raise IndexError("leaf index out of range")
    leaves = [leaf_hash(d) for d in data]

    def walk(m2: int, part: list[bytes]) -> list[bytes]:
        if len(part) == 1:
            return []
        k = _split(len(part))
        if m2 < k:
            return walk(m2, part[:k]) + [_root(part[k:])]
        return walk(m2 - k, part[k:]) + [_root(part[:k])]
    return walk(m, leaves)


def verify_inclusion(data: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    if not isinstance(index, int) or not isinstance(size, int) or not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf_hash(data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_path(m: int, data: list[bytes]) -> list[bytes]:
    """RFC 6962 2.1.2 PROOF(m, D[n])."""
    if not 1 <= m <= len(data):
        raise IndexError("old size out of range")
    leaves = [leaf_hash(d) for d in data]

    def sub(m2: int, part: list[bytes], whole: bool) -> list[bytes]:
        if m2 == len(part):
            return [] if whole else [_root(part)]
        k = _split(len(part))
        if m2 <= k:
            return sub(m2, part[:k], whole) + [_root(part[k:])]
        return sub(m2 - k, part[k:], False) + [_root(part[:k])]
    return sub(m, leaves, True)


def verify_consistency(size1: int, size2: int, root1: bytes, root2: bytes, path: list[bytes]) -> bool:
    """RFC 9162 2.1.4.2: the tree (size1, root1) is a prefix of the tree (size2, root2)."""
    if not isinstance(size1, int) or not isinstance(size2, int) or not 1 <= size1 <= size2:
        return False
    if size1 == size2:
        return not path and root1 == root2
    p = [root1, *path] if size1 & (size1 - 1) == 0 else list(path)
    if not p:
        return False
    fn, sn = size1 - 1, size2 - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root1 and sr == root2


def receipt_hash_bytes(h: str) -> bytes:
    if not isinstance(h, str) or not h.startswith("sha256:") or len(h) != 71:
        raise ValueError("not a sha256: receipt hash")
    return bytes.fromhex(h[7:])
