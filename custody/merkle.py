"""Minimal Merkle tree with inclusion proofs.

A Merkle tree lets a signer commit to a large batch of items with a single
32-byte root hash. Any single item can later be proven to belong to the
batch with a proof of ~log2(n) hashes, without shipping the whole batch.

Leaf and interior hashes are domain-separated (different one-byte prefixes)
so an interior node can never be presented as a leaf — the classic
second-preimage trick against naive Merkle constructions.

When a level has an odd number of nodes, the last node is carried up
unchanged (no duplication), so a datum's proof simply skips levels where
it had no sibling.
"""

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _sha256(_LEAF_PREFIX + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(_NODE_PREFIX + left + right)


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        raise ValueError("cannot build a Merkle tree over zero leaves")
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
        if len(cur) % 2:
            nxt.append(cur[-1])
        levels.append(nxt)
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    return _levels(leaves)[-1][0]


def merkle_proof(leaves: list[bytes], index: int) -> list[dict]:
    """Inclusion proof for leaves[index]: a list of {side, hash} steps."""
    levels = _levels(leaves)
    proof = []
    idx = index
    for level in levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            proof.append(
                {
                    "side": "left" if sibling < idx else "right",
                    "hash": level[sibling].hex(),
                }
            )
        idx //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[dict], root: bytes) -> bool:
    h = leaf
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        h = node_hash(sibling, h) if step["side"] == "left" else node_hash(h, sibling)
    return h == root
