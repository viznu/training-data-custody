"""Attestation emission: per-datum records, Merkle batching, ed25519 signing.

The operator running the cleaning pipeline holds an ed25519 signing key.
For each batch it emits:

  - one *record* per datum: {input_hash, output_hash, source, steps,
    pipeline_version, timestamp} — the claim "this exact output was produced
    from this exact input by this exact transform chain";
  - a Merkle tree over the record hashes;
  - one signed *manifest* per batch: {merkle_root, leaf_count,
    pipeline_version, batch_id, created_at}.

Each datum then travels as a self-contained *bundle*: cleaned content,
its record, its Merkle inclusion proof, and its index. One signature
covers the whole batch (that is what makes per-datum attestation cheap),
while the inclusion proof ties each individual datum to that signature.
Signing the leaf count in the manifest is what makes dataset-completeness
checks possible later.
"""

import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from custody.merkle import leaf_hash, merkle_proof, merkle_root
from custody.pipeline import DEFAULT_STEPS, canonical, pipeline_version, run_steps, sha256_hex

RECORD_FORMAT = "training-data-custody/record/1"
MANIFEST_FORMAT = "training-data-custody/manifest/1"


def make_record(raw: str, cleaned: str, steps: list[dict], source: dict, timestamp: str) -> dict:
    return {
        "format": RECORD_FORMAT,
        "input_hash": sha256_hex(raw.encode()),
        "output_hash": sha256_hex(cleaned.encode()),
        "source": source,
        "steps": steps,
        "pipeline_version": pipeline_version(steps),
        "timestamp": timestamp,
    }


def record_leaf(record: dict) -> bytes:
    return leaf_hash(canonical(record))


class Attestor:
    """The pipeline operator's signing identity."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._key = private_key or Ed25519PrivateKey.generate()
        self.public_key: Ed25519PublicKey = self._key.public_key()

    def attest(self, raw_docs: list[str], steps: list[dict] = DEFAULT_STEPS,
               batch_id: str = "batch-001", source_kind: str = "synthetic-demo") -> dict:
        """Clean each raw document and attest the (raw, cleaned) pairs."""
        pairs = [(raw, run_steps(raw, steps)) for raw in raw_docs]
        return self.attest_pairs(pairs, steps, batch_id, source_kind)

    def attest_pairs(self, pairs: list[tuple[str, str]], steps: list[dict],
                     batch_id: str, source_kind: str = "synthetic-demo") -> dict:
        """Low-level entry point: sign precomputed (raw, cleaned) pairs.

        Note the trust boundary: nothing here checks that `cleaned` really is
        `run_steps(raw, steps)`. A dishonest operator who wants to sign
        unprocessed or fabricated data would call exactly this. The signature
        proves *custody* (this key attested these bytes), not *correct
        execution* — closing that gap requires re-execution by the verifier
        (see verify.verify_reexecution) or attested execution (TEE/ZK).
        """
        timestamp = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
        records = [
            make_record(raw, cleaned, steps,
                        {"kind": source_kind, "id": f"{batch_id}/doc-{i:05d}"}, timestamp)
            for i, (raw, cleaned) in enumerate(pairs)
        ]
        leaves = [record_leaf(r) for r in records]
        root = merkle_root(leaves)
        manifest = {
            "format": MANIFEST_FORMAT,
            "batch_id": batch_id,
            "merkle_root": root.hex(),
            "leaf_count": len(leaves),
            "pipeline_version": pipeline_version(steps),
            "created_at": timestamp,
        }
        signature = self._key.sign(canonical(manifest))
        bundles = [
            {
                "content": cleaned,
                "record": records[i],
                "index": i,
                "proof": merkle_proof(leaves, i),
            }
            for i, (_, cleaned) in enumerate(pairs)
        ]
        return {
            "bundles": bundles,
            "manifest": manifest,
            "signature": signature.hex(),
            "public_key": self.public_key.public_bytes_raw().hex(),
        }
