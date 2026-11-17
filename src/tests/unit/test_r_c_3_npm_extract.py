"""R-C-3: npm export extraction. Entry points, modelled forms, the accounted-for rule,
the tokenizer, declaration files, star re-exports, and the two-entry rule.
declaration files, star re-exports, and the two-entry rule.

Each test builds a tarball in memory and calls the worker's extract_npm. The worker imports nothing
from the artifact, so calling it in-process is safe: it tokenizes text and matches token patterns.
Requirements: R-C-3, R-C-5. Properties: P-C-8 (JavaScript side) and P-C-1 (npm canary) are in
src/tests/properties and src/tests/integration.
"""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
from pathlib import Path

import pytest

from slopseal.contract import worker

MAX_FILE = 5 * 1024 * 1024
MAX_NAMES = 100_000


def _tarball(path: Path, files: dict[str, str], manifest: dict[str, object] | None) -> Path:
    members: dict[str, str] = {}
    if manifest is None:
        manifest = {"name": "pkg", "version": "1.0.0", "main": "index.js"}
    members["package/package.json"] = json.dumps(manifest)
    members.update({f"package/{name}": body for name, body in files.items()})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member, body in members.items():
            data = body.encode("utf-8")
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    path.write_bytes(buffer.getvalue())
    return path


def _extract(
    files: dict[str, str],
    manifest: dict[str, object] | None = None,
    *,
    max_file: int = MAX_FILE,
    max_names: int = MAX_NAMES,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        path = _tarball(Path(tmp) / "pkg.tgz", files, manifest)
        return worker.extract_npm(str(path), "package", max_file, max_names)


def _complete(files: dict[str, str], manifest: dict[str, object] | None = None) -> set[str]:
    result = _extract(files, manifest)
    assert result["status"] == "complete", result
    return set(result["exports"])  # type: ignore[arg-type]


def _unknown(files: dict[str, str], manifest: dict[str, object] | None = None) -> dict[str, object]:
    result = _extract(files, manifest)
    assert result["status"] == "unknown", result
    return result


# ---- CommonJS (Q2, Q4, Q5) ----------------------------------------------------------------------


def test_r_c_3_a_plain_object_literal_lists_its_keys() -> None:
    names = _complete({"index.js": "module.exports = { parse, stringify: fn, 'a-b': 1 };"})
    assert {"parse", "stringify", "a-b", "pkg.parse", "pkg.stringify"} <= names


def test_r_c_3_chained_exports_assignments_are_modelled() -> None:
    names = _complete({"index.js": "exports.a = 1; exports.b = exports.c = void 0;"})
    assert {"a", "b", "c", "pkg.a", "pkg.b", "pkg.c"} <= names


def test_r_c_3_module_exports_dot_name_is_modelled() -> None:
    assert "pkg.z" in _complete({"index.js": "module.exports.z = 1;"})


@pytest.mark.parametrize(
    "source",
    [
        "module.exports = function () {};",  # Q3
        "module.exports = new Thing();",  # Q2
        "module.exports = _;\n_.map = map;",  # Q2 then a member write
        "exports = {};",  # reassigned exports
        "var e = module.exports;",  # a read, not a rule
        "exports.a.b = 1;",  # a deeper write
        "module.exports = { ...base };",  # spread
        "module.exports = { [key]: 1 };",  # computed key
        "module.exports = { method() {} };",  # method
        "module.exports = { get x() { return 1; } };",  # accessor
        "module.exports = { default: 1 };",  # a literal key named default is not a rule
        "if (typeof module !== 'undefined') { exports.a = 1; }",  # typeof module
        "exports[name] = 1;",  # computed member write
    ],
)
def test_r_c_3_the_cjs_forms_outside_the_model_give_dynamic_exports(source: str) -> None:
    result = _unknown({"index.js": source})
    assert result["reason"] == "dynamic_exports"


def test_r_c_3_export_default_adds_default_q4() -> None:
    names = _complete({"index.js": "exports.default = 1;"})
    assert "default" in names
    assert "pkg.default" in names


# ---- Q5 helpers --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "__export(exports, { a: 1 });",
        "__exportStar(require('./x'), exports);",
        "__reExport(exports, require('./x'));",
        "__createBinding(exports, src, 'a');",
        "Object.defineProperty(exports, 'x', { get: function () { return 1; } });",
        "Object.assign(module.exports, { a: 1 });",
        "Object.keys(src).forEach((k) => { exports[k] = src[k]; });",
    ],
)
def test_r_c_3_bundler_helpers_and_getters_give_dynamic_exports(source: str) -> None:
    assert _unknown({"index.js": source})["reason"] == "dynamic_exports"


def test_r_c_3_defining_esmodule_is_ignored() -> None:
    source = "Object.defineProperty(exports, '__esModule', { value: true }); exports.x = 1;"
    names = _complete({"index.js": source})
    assert "x" in names
    assert "__esModule" not in names


# ---- The accounted-for rule ----------------------------------------------------------------------


def test_r_c_3_an_exports_token_in_a_comment_or_string_is_not_counted() -> None:
    names = _complete(
        {"index.js": "// module.exports = nope\nconst s = 'module.exports';\nexports.a = 1;"}
    )
    assert names >= {"a", "pkg.a"}


def test_r_c_3_an_exports_token_inside_a_template_substitution_is_counted() -> None:
    assert _unknown({"index.js": "const t = `${exports.a}`;"})["reason"] == "dynamic_exports"


def test_r_c_3_removing_the_accounted_for_rule_would_miss_a_read() -> None:
    """The read `console.log(exports.a)` is an unaccounted occurrence: UNKNOWN, not complete."""
    assert _unknown({"index.js": "console.log(exports.a); exports.b = 1;"})["reason"] == (
        "dynamic_exports"
    )


# ---- The tokenizer -------------------------------------------------------------------------------


def test_r_c_3_a_regex_before_exports_is_tokenized_correctly() -> None:
    """A slash that starts a regex must not turn the quote into a string (the M-DIV case)."""
    names = _complete({"index.js": 'const r = /"/; exports.a = 1; const s = "x";'})
    assert "a" in names
    assert "pkg.a" in names


@pytest.mark.parametrize(
    "source",
    [
        "const x = (1 + 2) / 2; exports.z = x;",  # division after a parenthesis
        "if (ok) /'/.test(s); exports.k = 1;",  # regex after if (...)
        "const y = a / b / c; exports.k = y;",  # division after identifiers
        "const z = [1] / 2; exports.k = z;",  # division after a bracket
        "const w = /[/]/g; exports.k = w;",  # a slash inside a character class
        "const v = 'a' / 2; exports.k = v;",  # division after a string
        "const u = x++ / 2; exports.k = u;",  # division after postfix ++
    ],
)
def test_r_c_3_slash_cases_either_tokenize_or_are_unknown_never_missed(source: str) -> None:
    result = _extract({"index.js": source})
    if result["status"] == "complete":
        assert "k" in result["exports"] or "z" in result["exports"]
    else:
        assert result["reason"] in ("parse_error", "dynamic_exports")


def test_r_c_3_a_slash_after_a_closing_brace_is_parse_error() -> None:
    result = _unknown({"index.js": "function f() {}\n/re/.test(s); exports.k = 1;"})
    assert result["reason"] == "parse_error"


@pytest.mark.parametrize(
    "source",
    [
        "exports.a = 'open",
        "/* not closed\nexports.a = 1;",
        "const t = `open ${x}",
        "const r = /open\nexports.a = 1;",
    ],
)
def test_r_c_3_an_unterminated_token_is_parse_error(source: str) -> None:
    assert _unknown({"index.js": source})["reason"] == "parse_error"


# ---- ESM (R-C-3) ---------------------------------------------------------------------------------


def test_r_c_3_esm_declaration_forms_are_named() -> None:
    names = _complete(
        {
            "index.js": (
                "export const a = 1;\nexport let b = 2;\nexport var c = 3;\n"
                "export function f() {}\nexport async function g() {}\n"
                "export function* h() {}\nexport class K {}\nexport default 1;\n"
            )
        }
    )
    assert {"a", "b", "c", "f", "g", "h", "K", "default"} <= names


def test_r_c_3_esm_export_list_with_rename_is_named() -> None:
    names = _complete({"index.js": "const x = 1; const y = 2; export { x, y as z };"})
    assert {"x", "z"} <= names
    assert "y" not in names


@pytest.mark.parametrize(
    "source",
    [
        "const a = 1; export { a as default };",  # the rename to default is not a rule
        "export const { a, b } = obj;",  # destructuring
        "export const a = 1, b = 2;",  # two declarators
        "export * as ns from './x';",  # namespace re-export
        "export * from 'lodash';",  # bare package
        "export { a } from 'lodash';",  # bare package in a list
        "export = thing;",  # not ESM, but still not modelled
        "export enum E {}",  # not a JavaScript form
    ],
)
def test_r_c_3_esm_forms_outside_the_model_give_dynamic_exports(source: str) -> None:
    assert _unknown({"index.js": source})["reason"] == "dynamic_exports"


def test_r_c_3_a_star_reexport_reads_its_target_one_hop() -> None:
    names = _complete({"index.js": "export * from './a';", "a.js": "export const q = 1;"})
    assert "q" in names


def test_r_c_3_a_star_reexport_with_a_second_hop_is_dynamic() -> None:
    files = {
        "index.js": "export * from './a';",
        "a.js": "export * from './b';",
        "b.js": "export const q = 1;",
    }
    assert _unknown(files)["reason"] == "dynamic_exports"


def test_r_c_3_a_star_reexport_of_a_missing_file_is_dynamic() -> None:
    assert _unknown({"index.js": "export * from './nowhere';"})["reason"] == "dynamic_exports"


# ---- Declaration files (R-C-3) -------------------------------------------------------------------

_TYPES = {"types": "index.d.ts"}


def test_r_c_3_declaration_forms_are_named() -> None:
    source = (
        "export declare function f(): void;\n"
        "export declare const enum E { A }\n"
        "export interface I {}\n"
        "export type T = string;\n"
        "export class C {}\n"
        "export namespace N {}\n"
        "export default X;\n"
    )
    names = _complete({"index.d.ts": source}, {"name": "pkg", "types": "index.d.ts"})
    assert {"f", "E", "I", "T", "C", "N", "default"} <= names


@pytest.mark.parametrize(
    "source",
    [
        "export = foo;",  # Q3
        "declare module 'x' { export const a: 1; }",  # declare module blocks
        "export as namespace Lib;",  # UMD global
        "export import a = require('x');",  # not modelled
    ],
)
def test_r_c_3_declaration_forms_outside_the_model_give_dynamic_exports(source: str) -> None:
    result = _extract({"index.d.ts": source}, {"name": "pkg", "types": "index.d.ts"})
    assert result["status"] == "unknown"
    assert result["reason"] == "dynamic_exports"


# ---- Entry points (R-C-3) ------------------------------------------------------------------------


def test_r_c_3_entry_with_no_fields_is_index_js() -> None:
    names = _complete({"index.js": "exports.a = 1;"}, {"name": "pkg"})
    assert "a" in names


def test_r_c_3_a_declared_entry_missing_from_the_tarball_is_parse_error() -> None:
    result = _unknown({"index.js": "exports.a = 1;"}, {"name": "pkg", "main": "lib/none.js"})
    assert result["reason"] == "parse_error"


@pytest.mark.parametrize("main", ["../x.js", "/abs.js", "a\\b.js"])
def test_r_c_3_an_unsafe_entry_path_is_parse_error(main: str) -> None:
    with pytest.raises(worker.Unsafe):
        _extract({"index.js": "exports.a = 1;"}, {"name": "pkg", "main": main})


def test_r_c_3_a_wildcard_subpath_is_dynamic_exports() -> None:
    with pytest.raises(worker.Dynamic):
        _extract({"index.js": "exports.a = 1;"}, {"name": "pkg", "exports": {"./*": "./*.js"}})


def test_r_c_3_typesversions_is_dynamic_exports() -> None:
    with pytest.raises(worker.Dynamic):
        _extract(
            {"index.js": "exports.a = 1;"},
            {"name": "pkg", "main": "index.js", "typesVersions": {"*": {}}},
        )


def test_r_c_3_an_unknown_condition_is_dynamic_exports() -> None:
    with pytest.raises(worker.Dynamic):
        _extract(
            {"index.js": "exports.a = 1;"},
            {"name": "pkg", "exports": {".": {"browser": "./index.js"}}},
        )


def test_r_c_3_a_literal_subpath_has_a_specifier_and_no_bare_names() -> None:
    files = {"index.js": "exports.root = 1;", "sub.js": "exports.inner = 2;"}
    manifest = {"name": "pkg", "exports": {".": "./index.js", "./sub": "./sub.js"}}
    names = _complete(files, manifest)
    assert "root" in names
    assert "inner" not in names  # bare names are for the root entry only
    assert "pkg/sub.inner" in names


def test_r_c_3_a_scoped_package_has_qualified_names() -> None:
    names = _complete({"index.js": "exports.a = 1;"}, {"name": "@scope/pkg", "main": "index.js"})
    assert "a" in names  # the bare name, from the root entry
    assert "@scope/pkg.a" in names  # the qualified name, for every entry (R-C-3)


# ---- Two entry points (R-C-3) --------------------------------------------------------------------

_TWO = {".": {"import": "./esm.js", "require": "./cjs.js"}}


def test_r_c_3_two_complete_entries_give_their_union() -> None:
    result = _extract(
        {"esm.js": "export const a = 1;", "cjs.js": "exports.b = 2;"},
        {"name": "pkg", "exports": _TWO},
    )
    assert result["status"] == "complete"
    assert {"a", "b"} <= set(result["exports"])  # type: ignore[arg-type]


def test_r_c_3_one_complete_and_one_not_keeps_the_complete_names_as_partial() -> None:
    result = _extract(
        {"esm.js": "export const a = 1;", "cjs.js": "module.exports = function () {};"},
        {"name": "pkg", "exports": _TWO},
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "dynamic_exports"
    partial = set(result["partial"])  # type: ignore[arg-type]
    assert "a" in partial  # PRESENT by the two-entry rule
    assert "stringify" not in partial  # not listed by a complete entry: UNKNOWN, never ABSENT


def test_r_c_3_no_complete_entry_gives_dynamic_exports_without_partial() -> None:
    result = _extract(
        {"esm.js": "module.exports = 1 + 1;", "cjs.js": "module.exports = function () {};"},
        {"name": "pkg", "exports": _TWO},
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "dynamic_exports"
    assert "partial" not in result


def test_r_c_3_a_single_entry_keeps_its_own_reason() -> None:
    result = _extract({"index.js": "module.exports = function () {};"}, {"name": "pkg"})
    assert result["reason"] == "dynamic_exports"


# ---- Limits (R-C-4) -----------------------------------------------------------------------------


def test_r_c_3_a_file_over_the_size_limit_is_limit() -> None:
    result = _extract({"index.js": "exports.a = 1;\n" + "// pad\n" * 200}, max_file=64)
    assert result["status"] == "unknown"
    assert result["reason"] == "limit"


def test_r_c_3_too_many_names_is_limit() -> None:
    with pytest.raises(worker.Limit):
        _extract({"index.js": "exports.a = 1; exports.b = 2;"}, max_names=2)


# ---- The tarball root (R-C-4) --------------------------------------------------------------------


def test_r_c_3_a_missing_package_json_at_the_root_is_parse_error() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        data = b"exports.a = 1;"
        info = tarfile.TarInfo("package/index.js")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "pkg.tgz"
        path.write_bytes(buffer.getvalue())
        with pytest.raises(worker.Unsafe):
            worker.extract_npm(str(path), "package", MAX_FILE, MAX_NAMES)


# ---- The top-level this (R-C-3, accounted-for rule) ----------------------------------------------


def test_r_c_3_a_top_level_this_is_module_exports_and_gives_dynamic_exports() -> None:
    assert _unknown({"index.js": "this.parse = parse;"})["reason"] == "dynamic_exports"


def test_r_c_3_a_this_inside_a_function_is_not_counted() -> None:
    source = "function Thing() { this.a = 1; }\nexports.Thing = Thing;"
    assert "Thing" in _complete({"index.js": source})


def test_r_c_3_a_template_substitution_keeps_brace_depth_exact() -> None:
    """After `${x}` the depth is back to zero, so a later export is still read (no false ABSENT)."""
    names = _complete({"index.js": "const t = `${1}`;\nexports.a = 1;"})
    assert "a" in names


# ---- Extensionless main, module, types, and typings (R-C-3, ruled at the 2.14 review) -----------


def test_r_c_3_an_extensionless_main_resolves_to_index_js() -> None:
    """The ms@2.1.3 shape: `"main": "./index"` with index.js in the tarball."""
    names = _complete({"index.js": "exports.ms = 1;"}, {"name": "ms", "main": "./index"})
    assert {"ms", "ms.ms"} <= names


def test_r_c_3_the_probe_order_for_main_is_js_then_cjs_then_mjs() -> None:
    """With index.cjs and index.mjs present and no index.js, the .cjs file wins over .mjs."""
    files = {
        "index.cjs": "exports.from_cjs = 1;",
        "index.mjs": "export const from_mjs = 1;",
    }
    names = _complete(files, {"name": "pkg", "main": "./index"})
    assert "from_cjs" in names
    assert "from_mjs" not in names


def test_r_c_3_an_extensionless_module_resolves_to_mjs() -> None:
    files = {"esm/index.mjs": "export const v = 1;"}
    names = _complete(files, {"name": "pkg", "module": "./esm/index"})
    assert "v" in names


def test_r_c_3_an_extensionless_types_path_resolves_to_d_ts_only() -> None:
    files = {"index.d.ts": "export declare function f(): void;"}
    names = _complete(files, {"name": "pkg", "types": "./index"})
    assert "f" in names


def test_r_c_3_an_extensionless_types_path_never_resolves_to_javascript() -> None:
    """index.js exists, but types probes only .d.ts: the declared entry is missing."""
    result = _unknown({"index.js": "exports.a = 1;"}, {"name": "pkg", "types": "./index"})
    assert result["reason"] == "parse_error"


def test_r_c_3_an_extensionless_main_with_no_probe_match_is_parse_error() -> None:
    result = _unknown({"other.js": "exports.a = 1;"}, {"name": "pkg", "main": "./missing"})
    assert result["reason"] == "parse_error"


def test_r_c_3_a_main_that_names_a_directory_is_parse_error() -> None:
    """A directory is not probed (R-C-3): lib/index.js is not found through `main: "./lib"`."""
    result = _unknown({"lib/index.js": "exports.a = 1;"}, {"name": "pkg", "main": "./lib"})
    assert result["reason"] == "parse_error"


def test_r_c_3_a_probed_entry_beside_a_missing_one_keeps_partial_names() -> None:
    """Two entries: `module` resolves by probe and `main` names a missing file. The
    probed entry's names are kept as partial."""
    files = {"esm/index.mjs": "export const v = 1;", "cjs.js": "exports.w = 2;"}
    manifest = {"name": "pkg", "module": "./esm/index", "main": "./nothere"}
    result = _extract(files, manifest)
    assert result["status"] == "unknown"
    assert result["reason"] == "dynamic_exports"
    assert "v" in set(result["partial"])  # type: ignore[arg-type]


# ---- Empty strings and the root name (R-C-3, ruled at the Run 1 review) --------------------------


def test_r_c_3_an_empty_main_is_absent_and_types_decides_the_entry() -> None:
    """The @types/semver shape: `"main": ""` and a declaration file. Only types counts."""
    files = {"index.d.ts": "export declare function parse(v: string): string;\n"}
    manifest = {"name": "pkg", "main": "", "types": "index.d.ts"}
    names = _complete(files, manifest)
    assert "parse" in names


def test_r_c_3_an_empty_main_with_no_other_field_falls_back_to_index_js() -> None:
    names = _complete({"index.js": "exports.a = 1;"}, {"name": "pkg", "main": ""})
    assert "a" in names


def test_r_c_3_an_empty_main_and_no_index_js_is_parse_error() -> None:
    result = _unknown({"lib.js": "exports.a = 1;"}, {"name": "pkg", "main": ""})
    assert result["reason"] == "parse_error"


def test_r_c_3_the_root_package_name_is_not_an_export_unless_exported() -> None:
    """npm:cookie: the bare probe `cookie` is ABSENT unless the package exports that symbol."""
    names = _complete({"index.js": "exports.parse = 1;"}, {"name": "cookie", "main": "index.js"})
    assert "cookie" not in names
    assert "cookie.cookie" not in names
    assert "cookie.parse" in names


def test_r_c_3_a_symbol_with_the_package_name_is_an_export_when_exported() -> None:
    names = _complete({"index.js": "exports.cookie = 1;"}, {"name": "cookie", "main": "index.js"})
    assert "cookie" in names
