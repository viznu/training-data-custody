# training-data-custody

A prototype of per-datum provenance attestations for training-data cleaning
pipelines. The pipeline emits a signed record for every document it
processes. A verifier holding a document, its record, and the operator's
public key can later check that the document is the exact output of a
declared transform chain, and, given a whole dataset, that nothing was added
or removed. The verifier keeps no state and needs no network access.

This is one piece of a larger question about chain of custody for training
data. Existing training-integrity work such as
[Proof-of-Learning](https://arxiv.org/abs/2103.05633) can establish that a
model was trained only on data from a specified dataset, but treats the
dataset as a trusted input. This repository addresses the cleaning-side half
of the question before that: whether the dataset's contents went through the
processing they claim. It was written under a ~90-minute time constraint and
is scoped accordingly.

## Design

1. Documents pass through a chain of pure, versioned transforms (here: strip
   HTML, normalize whitespace, redact email addresses). The transforms are
   deterministic, so anyone with a raw input and this code can re-derive the
   cleaned output independently.
2. Each datum gets a record: `{input_hash, output_hash, source, steps,
   pipeline_version, timestamp}`. Hashes are SHA-256; records are serialized
   as canonical JSON (sorted keys, no whitespace) so all parties hash the
   same bytes.
3. Records are batched under a Merkle tree, and the operator signs one
   manifest per batch with an ed25519 key: `{merkle_root, leaf_count,
   pipeline_version, batch_id, created_at}`. One signature covers the batch;
   a ~log2(n)-hash inclusion proof ties each datum to it. The signed
   `leaf_count` is what makes completeness checkable later.
4. Each datum travels as `{content, record, inclusion proof, index}` plus the
   shared manifest. Verification: content hashes to `output_hash`, the
   record's hash is included under the signed root, the signature is valid,
   and the key belongs to a trusted operator.

## Attack coverage

`demo.py` attests a 200-document synthetic corpus and runs the following
against the verifier:

| Attack | Per-datum check | Dataset check | Re-execution check |
|---|---|---|---|
| Tampering (bytes edited after attestation) | rejected | — | — |
| Forgery (attacker's own key) | rejected | — | — |
| Substitution (datum B under datum A's record) | rejected | — | — |
| Off-pipeline injection (fabricated record) | rejected | — | — |
| Cherry-picking (valid subset presented as the dataset) | accepted | rejected | — |
| Operator signs data it never cleaned | accepted | accepted | rejected¹ |
| Poisoned source, correctly cleaned | accepted | accepted | accepted |
| Stolen operator key | accepted | accepted | accepted² |

¹ Re-execution needs the raw input and the transform implementations, so it
is an optional stronger tier rather than something every downstream consumer
can run.

² Key custody is out of scope. A transparency log (as in
[Sigstore](https://www.sigstore.dev/)'s Rekor) would make misuse of a stolen
key detectable, not preventable.

## Limitations

- A signature proves custody, not correct execution. An operator holding the
  signing key can attest data it never cleaned, and the per-datum check
  accepts it (the demo shows this). Re-execution closes the gap when the raw
  input is available. Closing it without the raw input requires attested
  execution — a TEE or a zero-knowledge proof of the transform — which is not
  attempted here.
- Nothing here validates the source. A poisoned document that was faithfully
  cleaned verifies. Source attestation — proving a datum came from a specific
  origin at a specific time — is a separate problem, not attempted here.
- The corpus is synthetic (generated locally from a seeded RNG) and the
  transforms are toy versions, e.g. regex HTML stripping. Real pipelines also
  contain dataset-scale steps like global dedup, whose outputs depend on many
  inputs; the per-datum records defined here cannot express those.
- The dataset check proves the set is exactly what the operator attested,
  nothing about whether the corpus was any good.

## Running

Requires Python 3.11+ and
[`cryptography`](https://pypi.org/project/cryptography/) for ed25519.

```
pip install -r requirements.txt
python3 demo.py    # attack demonstration
```

## Layout

- `custody/pipeline.py` — transform registry, canonical JSON
- `custody/merkle.py` — Merkle tree with domain-separated leaves
- `custody/attest.py` — records, batching, manifest signing
- `custody/verify.py` — per-datum, dataset, and re-execution checks
- `custody/corpus.py` — seeded synthetic corpus
- `demo.py` — the attack demonstration

## References

[in-toto](https://in-toto.io/) · [SLSA](https://slsa.dev/) ·
[Sigstore](https://www.sigstore.dev/) · [C2PA](https://c2pa.org/) ·
[Proof-of-Learning](https://arxiv.org/abs/2103.05633) ·
[The Data Provenance Initiative](https://www.dataprovenance.org/)
