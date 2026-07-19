"""Per-datum provenance attestations for training-data cleaning pipelines.

A cleaning pipeline emits a signed, Merkle-batched attestation for every
datum it processes. A stateless verifier later checks, for any single datum,
that it is the exact output of a declared transform chain run by a known
operator, and, for a full dataset, that nothing was added or dropped.
"""

from custody.attest import Attestor
from custody.pipeline import DEFAULT_STEPS, run_steps
from custody.verify import verify_bundle, verify_dataset, verify_reexecution

__all__ = [
    "Attestor",
    "DEFAULT_STEPS",
    "run_steps",
    "verify_bundle",
    "verify_dataset",
    "verify_reexecution",
]
