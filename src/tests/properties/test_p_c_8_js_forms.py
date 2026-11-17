"""P-C-8, JavaScript side (R-C-3): synthetic npm artifacts for the completeness rules Q2 to Q5.

Each generated file holds one form from the rule's list, placed at random among otherwise modelled
statements. The extraction must never report a complete contract for such a file, so no probe can
be ABSENT. A one-entry package gives UNKNOWN with reason dynamic_exports. The oracle is the list of
forms in this file, not the extractor. The Q4 cases are the default export: a complete contract that
lists `default` (PRESENT), never ABSENT.

The tokenizer case is also here: a regular expression or a division before `exports.k = 1` must
either tokenize correctly (the contract is complete and lists k), or give UNKNOWN.
It is never missed.

Requirements: R-C-3. Property: P-C-8. Hypothesis runs 500 examples per property.
"""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from slopseal.contract import worker

MAX_FILE = 5 * 1024 * 1024
MAX_NAMES = 100_000
SYMBOL = st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True).filter(
    lambda s: s not in ("default", "module", "exports", "require", "pkg")
)
SYMBOLS = st.lists(SYMBOL, min_size=1, max_size=4, unique=True)

# Q2 (reassigned exports), Q3 (unnamed exports), Q5 (bundler helpers, defineProperty, assign).
# Each form is a dynamic form: the extraction gives UNKNOWN for the file.
DYNAMIC_FORMS_JS = [
    "module.exports = function () {};",
    "module.exports = new Thing();",
    "module.exports = _;\n_.map = map;",
    "module.exports = someIdentifier;",
    "__export(exports, { a: 1 });",
    "__exportStar(require('./x'), exports);",
    "__reExport(exports, require('./x'));",
    "__createBinding(exports, src, 'a');",
    "Object.defineProperty(exports, 'x', { get: function () { return 1; } });",
    "Object.assign(module.exports, { a: 1 });",
    "Object.keys(src).forEach((k) => { exports[k] = src[k]; });",
    "exports = { a: 1 };",
]
# Helpers that name no exports token: the helper rule alone must catch them (Q5, mutant M-Q5).
HELPER_ONLY_FORMS = [
    "__exportStar(require('./x'));",
    "__createBinding(target, source);",
]


def _modelled(symbols: list[str]) -> list[str]:
    return [f"exports.{symbol} = {index};\n" for index, symbol in enumerate(symbols)]


def _with_form(symbols: list[str], form: str, position: int) -> str:
    statements = _modelled(symbols)
    statements.insert(position % (len(statements) + 1), form + "\n")
    return "".join(statements)


def _extract(source: str) -> dict[str, object]:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        manifest = json.dumps({"name": "pkg", "version": "1.0.0", "main": "index.js"}).encode()
        for member, data in (
            ("package/package.json", manifest),
            ("package/index.js", source.encode()),
        ):
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.tgz"
        path.write_bytes(buffer.getvalue())
        return worker.extract_npm(str(path), "package", MAX_FILE, MAX_NAMES)


@given(
    symbols=SYMBOLS,
    form=st.sampled_from(DYNAMIC_FORMS_JS + HELPER_ONLY_FORMS),
    position=st.integers(0, 8),
)
def test_p_c_8_js_a_dynamic_form_is_never_a_complete_contract(
    symbols: list[str], form: str, position: int
) -> None:
    """Q2, Q3, Q5: for every probe the result is UNKNOWN, never ABSENT."""
    result = _extract(_with_form(symbols, form, position))
    assert result["status"] == "unknown", (form, result)
    assert result["reason"] == "dynamic_exports", (form, result)


@given(symbols=SYMBOLS, position=st.integers(0, 8))
def test_p_c_8_js_control_without_a_dynamic_form_is_complete(
    symbols: list[str], position: int
) -> None:
    """The control: the modelled file is complete and lists every symbol (no blanket UNKNOWN)."""
    result = _extract(_with_form(symbols, "", position))
    assert result["status"] == "complete", result
    listed = set(result["exports"])  # type: ignore[arg-type]
    for symbol in symbols:
        assert symbol in listed


@given(symbols=SYMBOLS, position=st.integers(0, 8))
def test_p_c_8_q4_default_is_present_and_never_absent(symbols: list[str], position: int) -> None:
    """Q4: `export default` and `exports.default =` add the reserved name default."""
    for form in ("export default function f() {}", "exports.default = value;"):
        result = _extract(_with_form(symbols, form, position))
        assert result["status"] == "complete", (form, result)
        assert "default" in set(result["exports"])  # type: ignore[arg-type]


@given(
    prefix=st.sampled_from(
        [
            'const r = /"/;',
            "const x = (1 + 2) / 2;",
            "if (ok) /'/.test(s);",
            "const y = a / b / c;",
            "const z = [1] / 2;",
            "const w = /[/]/g;",
            "const v = 'a' / 2;",
        ]
    ),
    name=SYMBOL,
)
def test_p_c_8_tokenizer_a_slash_before_exports_is_never_missed(prefix: str, name: str) -> None:
    """The slash cases tokenize correctly, so the export is read. They never give ABSENT."""
    result = _extract(f"{prefix}\nexports.{name} = 1;\nconst s = 'x';\n")
    if result["status"] == "complete":
        assert name in set(result["exports"])  # type: ignore[arg-type]
    else:
        assert result["reason"] in ("parse_error", "dynamic_exports")
