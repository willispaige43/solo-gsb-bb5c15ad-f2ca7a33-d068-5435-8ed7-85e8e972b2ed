"""Hand-written OpenAPI surface for the /commit, /verify and /diff endpoints.

Both routes deliberately accept a raw JSON :class:`fastapi.Request` (so they
can return the documented precise ``loc`` errors instead of Pydantic 422s),
which means FastAPI cannot infer their schemas automatically.  The Pydantic
models below describe the wire contract — including the two proof formats —
and :func:`install_openapi` merges them into the generated document while
keeping the auto-generated metadata for the health/index routes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

HexHash = Field(
    ...,
    pattern=r"^[0-9a-fA-F]{64}$",
    description="SHA-256 digest as 64 hexadecimal characters (32 bytes).",
)

COMMIT_EXAMPLE_DOC = {
    "subject": {"name": "Ada", "age": 36, "isAdult": True, "nickname": None},
    "emails": ["ada@example.com", "ada@analytical.engine"],
    "empty": {},
}


# ---------------------------------------------------------------------------
# Standard (legacy) format
# ---------------------------------------------------------------------------


class ProofStepModel(BaseModel):
    side: Literal["left", "right"] = Field(
        ..., description=(
            "Where the sibling sits relative to the running hash. "
            "`right` means H(running, sibling), `left` means "
            "H(sibling, running)."
        )
    )
    sibling: str = HexHash


class StandardCommitLeaf(BaseModel):
    path: str = Field(..., description="RFC 6901 pointer of the disclosed leaf.")
    value: Any = Field(..., description="Canonical leaf value (scalar or {} / []).")
    proof: List[ProofStepModel] = Field(
        ...,
        description="Sibling path from the leaf up to the root; empty for a "
        "single-leaf tree.",
    )


class StandardVerifyLeaf(StandardCommitLeaf):
    pass


class StandardCommitRequest(BaseModel):
    document: Any = Field(..., description="The nested JSON document to commit.")
    reveal: List[str] = Field(
        ..., description="RFC 6901 pointers of the leaves to disclose."
    )
    proofMode: Optional[Literal["standard"]] = Field(
        None,
        description="Omit or set to 'standard' for per-leaf {side, sibling} "
        "proofs (the backwards-compatible default).",
    )


class StandardCommitResponse(BaseModel):
    root: str = HexHash
    leaves: List[StandardCommitLeaf]


class StandardVerifyRequest(BaseModel):
    root: str = HexHash
    leaves: List[StandardVerifyLeaf]


# ---------------------------------------------------------------------------
# Compact multi-leaf format
# ---------------------------------------------------------------------------


class ProofNodeModel(BaseModel):
    level: int = Field(
        ...,
        ge=0,
        description=(
            "Tree level, 0-indexed from the leaf level.  Level 0 is the leaf "
            "level; the root is at the final level and is never listed."
        ),
    )
    index: int = Field(
        ...,
        ge=0,
        description=(
            "Position of the node within its level.  Each (level, index) "
            "pair appears at most once in the whole proof."
        ),
    )
    hash: str = HexHash


class CompactCommitLeaf(BaseModel):
    path: str = Field(..., description="RFC 6901 pointer of the disclosed leaf.")
    index: int = Field(
        ...,
        ge=0,
        description=(
            "Zero-based position of the leaf in the sorted-by-pointer leaf "
            "set (the same ordering used to build the root)."
        ),
    )
    value: Any = Field(..., description="Canonical leaf value (scalar or {} / []).")


class CompactCommitRequest(BaseModel):
    document: Any = Field(..., description="The nested JSON document to commit.")
    reveal: List[str] = Field(
        ..., description="RFC 6901 pointers of the leaves to disclose."
    )
    proofMode: Literal["compact"] = Field(
        ...,
        description="Selects the deduplicated multi-leaf proof format.",
    )


class CompactCommitResponse(BaseModel):
    root: str = HexHash
    proofMode: Literal["compact"]
    leafCount: int = Field(
        ...,
        ge=1,
        description="Total number of leaves the committed tree was built "
        "from (the verifier needs it to know each level's width).",
    )
    leaves: List[CompactCommitLeaf]
    proofNodes: List[ProofNodeModel] = Field(
        ...,
        description=(
            "Sibling nodes required by the fold, unique by (level, index) "
            "and sorted level-first.  A sibling needed by several disclosed "
            "leaves occurs exactly once.  The last node of an odd-sized "
            "level is never listed: it is paired with a copy of itself."
        ),
    )


class CompactVerifyRequest(BaseModel):
    root: str = HexHash
    leafCount: int = Field(..., ge=1)
    leaves: List[CompactCommitLeaf]
    proofNodes: List[ProofNodeModel]


# ---------------------------------------------------------------------------
# Leaf-level document diff
# ---------------------------------------------------------------------------


class DiffRequest(BaseModel):
    before: Any = Field(..., description="The original JSON document.")
    after: Any = Field(..., description="The updated JSON document.")
    paths: Optional[List[str]] = Field(
        None,
        description=(
            "Optional filter: restrict the report to these RFC 6901 leaf "
            "paths.  Every entry must name an exact leaf in at least one of "
            "the two documents; duplicates, non-leaf paths and unknown "
            "paths are rejected with a precise `loc`."
        ),
    )


class DiffEntry(BaseModel):
    path: str = Field(..., description="RFC 6901 pointer of the leaf.")
    before: Any = Field(
        None,
        description=(
            "Leaf value in the `before` document; null when the leaf does "
            "not exist there.  A genuine JSON null also serializes as null "
            "— use `beforeFingerprint` to tell the two apart."
        ),
    )
    after: Any = Field(
        None,
        description=(
            "Leaf value in the `after` document; null when the leaf does "
            "not exist there (see `beforeFingerprint`)."
        ),
    )
    beforeFingerprint: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description=(
            "SHA-256 of the canonical `before` value; null when the leaf "
            "is absent from the `before` document."
        ),
    )
    afterFingerprint: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description=(
            "SHA-256 of the canonical `after` value; null when the leaf "
            "is absent from the `after` document."
        ),
    )


class DiffResponse(BaseModel):
    added: List[DiffEntry] = Field(
        ..., description="Leaves present only in `after`, sorted by path."
    )
    removed: List[DiffEntry] = Field(
        ..., description="Leaves present only in `before`, sorted by path."
    )
    changed: List[DiffEntry] = Field(
        ...,
        description="Leaves present in both whose canonical value differs, "
        "sorted by path.",
    )


# ---------------------------------------------------------------------------
# Shared responses / errors
# ---------------------------------------------------------------------------


class VerifiedLeaf(BaseModel):
    path: str
    value: Any


class StandardVerifyResponse(BaseModel):
    valid: bool = True
    root: str = HexHash
    leaves: List[VerifiedLeaf]


class CompactVerifyResponse(StandardVerifyResponse):
    proofMode: Literal["compact"]


class ErrorDetail(BaseModel):
    code: str
    message: str
    loc: Optional[str] = Field(
        None, description="JSON-Pointer-style location of the offending field."
    )
    detail: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


def _ref(name: str) -> Dict[str, Any]:
    return {"$ref": f"#/components/schemas/{name}"}


def _model_schemas(*models: type[BaseModel]) -> Dict[str, Any]:
    """Return {name: schema} for the models, inlining any ``$defs``."""
    schemas: Dict[str, Any] = {}
    for model in models:
        generated = model.model_json_schema(
            ref_template="#/components/schemas/{model}"
        )
        defs = generated.pop("$defs", {})
        for name, schema in defs.items():
            schemas.setdefault(name, schema)
        schemas[model.__name__] = generated
    return schemas


def _json_content(schema: Dict[str, Any], example: Any = None) -> Dict[str, Any]:
    content: Dict[str, Any] = {
        "content": {"application/json": {"schema": schema}}
    }
    if example is not None:
        content["content"]["application/json"]["example"] = example
    return content


def install_openapi(app: FastAPI) -> None:
    """Replace the auto-generated OpenAPI document with the full contract."""

    def _openapi() -> Dict[str, Any]:
        cached = getattr(app, "_custom_openapi_schema", None)
        if cached is not None:
            return cached

        generated = app._orig_openapi()  # type: ignore[attr-defined]

        components = generated.setdefault("components", {}).setdefault(
            "schemas", {}
        )
        components.update(
            _model_schemas(
                ProofStepModel,
                StandardCommitRequest,
                StandardCommitResponse,
                StandardVerifyRequest,
                ProofNodeModel,
                CompactCommitRequest,
                CompactCommitResponse,
                CompactVerifyRequest,
                StandardVerifyResponse,
                CompactVerifyResponse,
                DiffRequest,
                DiffEntry,
                DiffResponse,
                ErrorResponse,
            )
        )

        error_responses = {
            "400": {"description": "Structural/input error (BAD_PROOF, "
                    "INVALID_REQUEST, POINTER_SYNTAX, ...)",
                    **_json_content(_ref("ErrorResponse"))},
            "413": {"description": "Request body exceeds MAX_BODY_BYTES",
                    **_json_content(_ref("ErrorResponse"))},
            "422": {"description": "ROOT_MISMATCH: structurally valid proof "
                    "that does not rebuild the committed root",
                    **_json_content(_ref("ErrorResponse"))},
        }

        commit_request_schema = {
            "oneOf": [
                _ref("StandardCommitRequest"),
                _ref("CompactCommitRequest"),
            ]
        }
        commit_response_schema = {
            "oneOf": [
                _ref("StandardCommitResponse"),
                _ref("CompactCommitResponse"),
            ]
        }
        verify_request_schema = {
            "oneOf": [
                _ref("StandardVerifyRequest"),
                _ref("CompactVerifyRequest"),
            ],
            "description": (
                "The format is detected automatically: a body containing "
                "`proofNodes`/`leafCount` is treated as a compact proof; "
                "otherwise each leaf must carry a standard `proof` array."
            ),
        }
        verify_response_schema = {
            "oneOf": [
                _ref("StandardVerifyResponse"),
                _ref("CompactVerifyResponse"),
            ]
        }

        generated["paths"]["/commit"] = {
            "post": {
                "summary": "Commit a document and generate disclosure proofs",
                "description": (
                    "Expands the document into sorted RFC 6901 leaves, "
                    "builds the reproducible Merkle root and returns, for "
                    "each requested leaf, its value plus an inclusion "
                    "proof. With `proofMode: \"compact\"` the response "
                    "carries `leafCount`, a per-leaf sorted `index` and one "
                    "deduplicated `proofNodes` array; without it, the "
                    "response keeps the legacy per-leaf `proof` shape."
                ),
                "operationId": "commit",
                "requestBody": _json_content(
                    commit_request_schema,
                    example={
                        "document": COMMIT_EXAMPLE_DOC,
                        "reveal": ["/subject/age", "/emails/1", "/empty"],
                        "proofMode": "compact",
                    },
                ),
                "responses": {
                    "200": {
                        "description": "Root and disclosures (only selected "
                        "leaves are returned)",
                        **_json_content(
                            commit_response_schema,
                            example={
                                "root": "9f0c000000000000000000000000000000000000000000000000000000000000",
                                "proofMode": "compact",
                                "leafCount": 8,
                                "leaves": [
                                    {"path": "/emails/1", "index": 2,
                                     "value": "ada@analytical.engine"},
                                    {"path": "/empty", "index": 3,
                                     "value": {}},
                                    {"path": "/subject/age", "index": 5,
                                     "value": 36},
                                ],
                                "proofNodes": [
                                    {"level": 0, "index": 0,
                                     "hash": "ab" * 32},
                                    {"level": 1, "index": 1,
                                     "hash": "cd" * 32},
                                ],
                            },
                        ),
                    },
                    **error_responses,
                },
            }
        }

        generated["paths"]["/verify"] = {
            "post": {
                "summary": "Verify disclosures against a committed root",
                "description": (
                    "Statelessly rebuilds the root from the disclosed leaf "
                    "values and the proof. The compact shape is rebuilt "
                    "bottom-up from `leafCount`, the per-leaf `index` and "
                    "the unique `{level,index,hash}` proof nodes. Index "
                    "range/uniqueness, the odd-level last-node duplication "
                    "rule and missing/extraneous proof nodes are structural "
                    "errors (400 BAD_PROOF with a precise `loc`); a valid "
                    "structure that folds to another root is 422 "
                    "ROOT_MISMATCH."
                ),
                "operationId": "verify",
                "requestBody": _json_content(
                    verify_request_schema,
                    example={
                        "root": "9f0c000000000000000000000000000000000000000000000000000000000000",
                        "leafCount": 8,
                        "leaves": [
                            {"path": "/subject/age", "index": 5, "value": 36}
                        ],
                        "proofNodes": [
                            {"level": 0, "index": 4, "hash": "ab" * 32},
                            {"level": 1, "index": 3, "hash": "cd" * 32},
                            {"level": 2, "index": 0, "hash": "ef" * 32},
                        ],
                    },
                ),
                "responses": {
                    "200": {
                        "description": "All disclosures rebuild the committed "
                        "root",
                        **_json_content(verify_response_schema),
                    },
                    **error_responses,
                },
            }
        }

        generated["paths"]["/diff"] = {
            "post": {
                "summary": "Report leaf-level changes between two documents",
                "description": (
                    "Expands `before` and `after` into RFC 6901 leaves with "
                    "the same rules as /commit (scalars, null and empty "
                    "containers are leaves; a scalar or empty root document "
                    "is the single root leaf `\"\"`), aligns the two sorted "
                    "path sets and reports `added`, `removed` and `changed` "
                    "groups.  Each entry carries the path, the old/new "
                    "value (null on the missing side) and the SHA-256 "
                    "fingerprint of the corresponding canonical value.  "
                    "Values are compared by canonical form, so 1, 1.0 and "
                    "true are three different values.  The optional `paths` "
                    "filter narrows the report to exact leaf paths; "
                    "duplicates, non-leaf paths and unknown paths fail the "
                    "whole request with a locatable 400 error."
                ),
                "operationId": "diff",
                "requestBody": _json_content(
                    _ref("DiffRequest"),
                    example={
                        "before": {
                            "subject": {"name": "Ada", "age": 36},
                            "emails": ["ada@example.com"],
                            "nickname": None,
                        },
                        "after": {
                            "subject": {"name": "Ada", "age": 37},
                            "emails": ["ada@example.com",
                                       "ada@analytical.engine"],
                        },
                        "paths": ["/subject/age", "/emails/1", "/nickname"],
                    },
                ),
                "responses": {
                    "200": {
                        "description": "Sorted added/removed/changed leaf "
                        "groups",
                        **_json_content(
                            _ref("DiffResponse"),
                            example={
                                "added": [
                                    {
                                        "path": "/emails/1",
                                        "before": None,
                                        "after": "ada@analytical.engine",
                                        "beforeFingerprint": None,
                                        "afterFingerprint": "ab" * 32,
                                    }
                                ],
                                "removed": [
                                    {
                                        "path": "/nickname",
                                        "before": None,
                                        "after": None,
                                        "beforeFingerprint": "cd" * 32,
                                        "afterFingerprint": None,
                                    }
                                ],
                                "changed": [
                                    {
                                        "path": "/subject/age",
                                        "before": 36,
                                        "after": 37,
                                        "beforeFingerprint": "ef" * 32,
                                        "afterFingerprint": "09" * 32,
                                    }
                                ],
                            },
                        ),
                    },
                    "400": {"description": "Structural/input error "
                            "(INVALID_REQUEST, POINTER_SYNTAX, "
                            "PATH_NOT_LEAF, DUPLICATE_PATH, ...)",
                            **_json_content(_ref("ErrorResponse"))},
                    "413": {"description": "Request body exceeds "
                            "MAX_BODY_BYTES",
                            **_json_content(_ref("ErrorResponse"))},
                },
            }
        }

        app._custom_openapi_schema = generated
        return generated

    # Stash the original generator before swapping it in.
    app._orig_openapi = app.openapi  # type: ignore[attr-defined]
    app.openapi = _openapi  # type: ignore[method-assign]
