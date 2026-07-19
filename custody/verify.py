"""Stateless verification of attestation bundles.

The verifier needs only: a bundle, the batch manifest + signature, and a set
of trusted operator public keys. No database, no network, no state.

Three verification tiers, in increasing strength and cost:

  1. verify_bundle    — per-datum: the datum is bit-identical to something a
                        trusted operator attested. Cheap (one signature check,
                        one hash, ~log2(n) hashes for inclusion).
  2. verify_dataset   — dataset-level: additionally, the presented collection
                        is *exactly* the attested batch — nothing added,
                        nothing dropped. Defeats cherry-picking.
  3. verify_reexecution — with the raw input in hand, re-run the declared
                        transform chain and compare outputs. Defeats an
                        operator that signed data it never actually cleaned.

None of the three validates the original *source* of the raw data; that is
the separate source-attestation problem.
"""

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from custody.attest import record_leaf
from custody.merkle import merkle_root, verify_proof
from custody.pipeline import REGISTRY, canonical, run_steps, sha256_hex


@dataclass
class Result:
    ok: bool
    reason: str

    def __bool__(self) -> bool:
        return self.ok


def _check_manifest_signature(manifest: dict, signature_hex: str, public_key_hex: str,
                              trusted_keys: set[str]) -> Result:
    if public_key_hex not in trusted_keys:
        return Result(False, "signer's public key is not a trusted operator key")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        key.verify(bytes.fromhex(signature_hex), canonical(manifest))
    except InvalidSignature:
        return Result(False, "manifest signature is invalid")
    return Result(True, "manifest signed by trusted key")


def verify_bundle(bundle: dict, manifest: dict, signature_hex: str, public_key_hex: str,
                  trusted_keys: set[str]) -> Result:
    """Per-datum check: content -> record -> Merkle root -> signature -> trusted key."""
    sig = _check_manifest_signature(manifest, signature_hex, public_key_hex, trusted_keys)
    if not sig:
        return sig

    record = bundle["record"]
    if sha256_hex(bundle["content"].encode()) != record["output_hash"]:
        return Result(False, "content does not match the attested output_hash")

    if record["pipeline_version"] != manifest["pipeline_version"]:
        return Result(False, "record claims a different pipeline_version than the manifest")

    root = bytes.fromhex(manifest["merkle_root"])
    if not verify_proof(record_leaf(record), bundle["proof"], root):
        return Result(False, "record is not included under the signed Merkle root")

    return Result(True, "datum verifies against the signed batch")


def verify_dataset(bundles: list[dict], manifest: dict, signature_hex: str,
                   public_key_hex: str, trusted_keys: set[str]) -> Result:
    """Completeness check: the presented bundles are exactly the attested batch."""
    sig = _check_manifest_signature(manifest, signature_hex, public_key_hex, trusted_keys)
    if not sig:
        return sig

    if len(bundles) != manifest["leaf_count"]:
        return Result(
            False,
            f"dataset has {len(bundles)} datums but the signed manifest "
            f"attests {manifest['leaf_count']} — data was dropped or added",
        )

    indices = sorted(b["index"] for b in bundles)
    if indices != list(range(manifest["leaf_count"])):
        return Result(False, "bundle indices are not exactly 0..leaf_count-1")

    for b in bundles:
        per_datum = verify_bundle(b, manifest, signature_hex, public_key_hex, trusted_keys)
        if not per_datum:
            return Result(False, f"datum {b['index']}: {per_datum.reason}")

    ordered = sorted(bundles, key=lambda b: b["index"])
    rebuilt = merkle_root([record_leaf(b["record"]) for b in ordered])
    if rebuilt.hex() != manifest["merkle_root"]:
        return Result(False, "rebuilt Merkle root does not match the signed root")

    return Result(True, "dataset is exactly the attested batch, nothing added or dropped")


def verify_reexecution(raw: str, bundle: dict) -> Result:
    """Independently re-run the declared transform chain on the raw input.

    Requires the raw datum and the transform implementations, so it is not
    always available downstream — but when it is, it removes the need to
    trust that the operator actually executed the pipeline it claims.
    """
    record = bundle["record"]
    if sha256_hex(raw.encode()) != record["input_hash"]:
        return Result(False, "provided raw datum does not match the attested input_hash")
    for step in record["steps"]:
        if (step["transform_id"], step["version"]) not in REGISTRY:
            return Result(False, f"unknown transform {step['transform_id']}@{step['version']}")
    rederived = run_steps(raw, record["steps"])
    if sha256_hex(rederived.encode()) != record["output_hash"]:
        return Result(
            False,
            "re-running the declared steps does not reproduce the attested "
            "output — the operator signed something it did not actually run",
        )
    return Result(True, "declared transform chain independently reproduces the output")
