"""A small, deterministic cleaning pipeline with a transform registry.

Every transform is a pure function (text, params) -> text, registered under
a (transform_id, version) key. Determinism is load-bearing: because the
same input, step chain, and params always produce the same output, anyone
holding a raw datum and this code can re-derive the cleaned output and its
hash, independently of the operator's signature. That upgrades trust from
"the operator's key said so" to "the operator's key said so, OR I re-ran
the transform myself and got the same bytes".
"""

import hashlib
import html
import json
import re


def canonical(obj) -> bytes:
    """Canonical JSON serialization: sorted keys, no whitespace, UTF-8.

    Signatures and hashes are computed over these bytes so that two parties
    serializing the same logical record always hash the same bytes.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


REGISTRY: dict[tuple[str, str], callable] = {}


def register(transform_id: str, version: str):
    def deco(fn):
        REGISTRY[(transform_id, version)] = fn
        return fn

    return deco


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


@register("strip_html", "1")
def strip_html(text: str, params: dict) -> str:
    return html.unescape(_TAG_RE.sub(" ", text))


@register("normalize_whitespace", "1")
def normalize_whitespace(text: str, params: dict) -> str:
    return _WS_RE.sub(" ", text).strip()


@register("redact_emails", "1")
def redact_emails(text: str, params: dict) -> str:
    return _EMAIL_RE.sub(params["placeholder"], text)


DEFAULT_STEPS = [
    {"transform_id": "strip_html", "version": "1", "params": {}},
    {"transform_id": "normalize_whitespace", "version": "1", "params": {}},
    {"transform_id": "redact_emails", "version": "1", "params": {"placeholder": "[EMAIL]"}},
]


def run_steps(text: str, steps: list[dict]) -> str:
    for step in steps:
        fn = REGISTRY[(step["transform_id"], step["version"])]
        text = fn(text, step["params"])
    return text


def pipeline_version(steps: list[dict]) -> str:
    """A single hash identifying the full step chain, versions, and params."""
    return sha256_hex(canonical(steps))
