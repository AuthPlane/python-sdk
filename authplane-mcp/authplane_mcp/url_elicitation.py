"""URL elicitation primitive for the MCP adapter.

The factory function :func:`authplane_mcp.authplane_mcp_auth` wraps the
``AuthplaneClient`` it returns so that ``client.exchange()`` consent errors
auto-translate into MCP ``-32042`` (URL elicitation required) before user
tool code sees them.  This module exposes the underlying conversion as a
small primitive for unusual flows where users build a consent error outside
the wrapped client and want to raise the MCP-shaped error themselves.

NOTE: this module is mirrored byte-for-byte in
``authplane-fastmcp/authplane_fastmcp/url_elicitation.py`` except for the
adapter name in the docstrings and the package name in the error string below.
Any fix here — in particular the eventual mcp-2.0 elicitation-field port — must
be applied to both copies.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from authplane.errors import ConsentRequiredError
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import ElicitRequestURLParams

if TYPE_CHECKING:
    from pydantic import BaseModel


@functools.cache
def _resolve_elicitation_id_kwarg(model: type[BaseModel]) -> str:
    """Resolve the constructor kwarg for the elicitation-id field from the
    model's own schema.

    mcp 1.x spells the field camelCase ``elicitationId``; mcp 2.0 renames it to
    snake_case ``elicitation_id``. We look the name up *positively* from the
    model rather than trying ``elicitationId=`` and catching ``ValidationError``:
    ``ElicitRequestURLParams`` is declared ``extra="allow"``, so if a future
    release renamed the field to an *optional* one, the camelCase kwarg would be
    silently absorbed into ``__pydantic_extra__``, the renamed field would stay
    unset, and no ``ValidationError`` would be raised — the client would then get
    a ``-32042`` with no id at all (a silent failure worse than the 500 the
    try/except was meant to prevent). That guard also swallowed unrelated
    validation errors (e.g. a malformed ``url``) and was a pyright-strict call
    error.

    Cached (``functools.cache``) keyed by the model class, so resolution is cheap
    enough to run per build call; that keeps it lazy — a test can patch the
    module's ``ElicitRequestURLParams`` and exercise the resolve→build wiring
    without patching any resolved module state.
    """
    fields = model.model_fields
    for name in ("elicitationId", "elicitation_id"):
        field = fields.get(name)
        if field is not None:
            # A rename can arrive as an alias rather than a field rename.
            # Pydantic resolves a validation kwarg by ``validation_alias`` when
            # it is set, falling back to the generic ``alias``; mirror that order
            # here. A non-str validation alias — AliasPath / AliasChoices, e.g.
            # from ``validation_alias=AliasChoices(...)`` — is not a usable single
            # kwarg, so fall through to the generic alias, else the field name.
            if isinstance(field.validation_alias, str):
                return field.validation_alias
            if field.alias is not None:
                return field.alias
            return name
    # Neither known spelling is a declared field. With ``extra="allow"`` a
    # default kwarg would land silently in ``__pydantic_extra__`` (a ``-32042``
    # with no id). The ``mcp<2`` ceiling means this branch can only be reached
    # inside mcp 1.x, so a third spelling is an unexpected schema change: fail
    # loudly rather than emit a malformed elicitation.
    # RuntimeError, not ImportError: this resolver runs both at import time (where
    # ImportError is the right shape) and lazily from
    # ``_build_url_elicitation_params``, where the installed package imported
    # fine and the failure is a runtime schema mismatch. ImportError from a
    # non-import call site sends the reader looking for a missing dependency.
    raise RuntimeError(
        f"authplane-mcp cannot resolve the elicitation-id field on {model.__name__!r}: "
        "none of the known spellings (elicitationId, elicitation_id) is a declared "
        "field. The installed mcp is not compatible; require mcp>=1.28.1,<2."
    )


# Fail fast at import: the installed mcp must expose a known elicitation-id
# spelling. Resolution is otherwise lazy (see _build_url_elicitation_params) so
# tests can patch the model without re-triggering this. The name below is never
# read — it is bound only so this validation runs as an import-time side effect.
#
# The resolver raises RuntimeError because it is also called lazily, where the
# package imported fine and the failure is a runtime schema mismatch. At *this*
# call site the failure really is "the installed distribution is unusable", so
# translate it to the shape a reader expects from a failing import.
try:
    _ELICITATION_ID_KWARG = _resolve_elicitation_id_kwarg(ElicitRequestURLParams)
except RuntimeError as exc:  # pragma: no cover - exercised via importlib.reload
    raise ImportError(str(exc)) from exc


def _build_url_elicitation_params(
    *, url: str, message: str, elicitation_id: str
) -> ElicitRequestURLParams:
    """Construct ``ElicitRequestURLParams`` under the elicitation-id field name
    the installed mcp uses (camelCase ``elicitationId`` on 1.x, snake_case
    ``elicitation_id`` on 2.0), resolved from the model's own schema.
    """
    # Resolve lazily from the module-level model so a test can patch only
    # ``ElicitRequestURLParams`` and have this composition pick up the change.
    # ``kwargs`` is typed ``dict[str, Any]`` because the model's params are not
    # all ``str``; that silences the pyright-strict reportCallIssue on unpack.
    kwargs: dict[str, Any] = {
        _resolve_elicitation_id_kwarg(ElicitRequestURLParams): elicitation_id,
        "mode": "url",
        "url": url,
        "message": message,
    }
    return ElicitRequestURLParams(**kwargs)


def to_url_elicitation_required_error(
    error: BaseException,
) -> UrlElicitationRequiredError | None:
    """Map a :class:`ConsentRequiredError` with a ``consent_url`` to MCP -32042.

    Returns ``None`` for any other input — non-consent errors and consent
    errors without a ``consent_url`` are not translatable.  Callers then
    re-raise the original exception unchanged.
    """
    if not isinstance(error, ConsentRequiredError) or not error.consent_url:
        return None

    return UrlElicitationRequiredError(
        elicitations=[
            _build_url_elicitation_params(
                url=error.consent_url,
                message=error.describe(),
                elicitation_id=str(uuid4()),
            )
        ],
        message=str(error),
    )
