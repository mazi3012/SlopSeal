
# SlopSeal v2: Requirements

**Relation to v1:** `.kiro/specs/seal/` is the v1 contract and stays unchanged. v2 adds requirements. Where a v2 requirement changes a v1 statement, the v2 requirement names the v1 statement it supersedes. v1 files are not edited.
**Format:** EARS (Easy Approach to Requirements Syntax).
**Requirement IDs:** `R-<area>-<n>`. Commit messages cite them, for example `feat(hooks): verdict-aware hook [R-G-1]`.

| Prefix | Area | Phase | Status |
|--------|------|-------|--------|
| `R-G-*` | Gate: the Kiro install hook | 1 (`feat/v2-hook`) | Specified below |
| `R-C-*` | Contract Check | 2 (`feat/v2-contract`) | Specified in section 2. Not implemented |
| `R-S-*` | Signing: Ed25519 seals behind an optional extra | 3 (not scheduled) | Reserved. Needs ADR-0004 before any code |

**Glossary**

- **Gate (`R-G`)**: the Kiro install hook. It runs `verify_install` for each pinned pip or npm package in an agent command.
- **Contract Check (`R-C`)**: Phase 2. It reads what a package really exports, statically, from the artifact the registry serves for one exact version, so that an intent check can answer PRESENT, ABSENT, or UNKNOWN. Specified in section 2. Not implemented.
- **Signing (`R-S`)**: Ed25519 seals behind the optional `slopseal[sign]` extra. Needs ADR-0004.
- **T17, T18, T23**: threats that Phase 2 addresses. T17 is a hostile artifact (archive bomb, path traversal, code run while the artifact is read). T18 is an artifact that builds its exports at run time to dodge the check. T23 is an artifact that does not match the digest the registry published. Mapped to R-C-1 to R-C-5. **Not implemented.** T19 to T22 are reserved for later phases and are not used in Phase 2.
- **T16**: transitive dependencies of a package that passes. Mapped to **R-G-12** (depth-1 transitive check). **Not implemented.** Phase 4 ships it. T16 stays open until then. R-G-4 is the QUARANTINE rule and does not cover transitive checks.

Terms used below:

- **Install** (for the hook): a simple command in the hook payload's `tool_input.command` that the v1 hook detects as an install. Detection is unchanged from v1.
- **Verifiable install**: an install that `slopseal.intercept.parse` turns into one or more registry packages, each at an exact version. That covers `pip install name==x.y.z`, `npm install name@x.y.z`, and `npx`, `npm exec`, `npm x` with `name@x.y.z`.
- **Unverifiable install**: any other install.

---

## 1. Gate: the verdict-aware install hook

**R-G-1 (verdict per package).** When the hook payload's `tool_input.command` contains a verifiable install, the system shall call `verify_install` once for each distinct package and exact version that the command names, without an intent. Each call is an install attempt for the rate limit (R-4.7).

**R-G-2 (ALLOW).** When every call under R-G-1 returns ALLOW and the command contains no unverifiable install, the system shall exit 0, so the command runs. The system shall write one summary line per package, and any warnings, to stderr.

**R-G-3 (BLOCK).** When any call under R-G-1 returns BLOCK, the system shall exit 2. For each blocked package the system shall write to stderr the package, the version, the failed check, the reason, and a suggested fix. The suggested fix is the check's remedy when it has one, and a fixed fallback text otherwise.

**R-G-4 (QUARANTINE).** When any call under R-G-1 returns QUARANTINE, the system shall exit 2. For each quarantined package the system shall write to stderr the package, the version, the check name (`mismatch_type`), the `quarantine_id`, and the next step.

**R-G-5 (unverifiable installs).** When the command contains an unverifiable install, the system shall exit 2 and write the reason and a suggested fix to stderr. Unverifiable includes: an unpinned name or a version range, a URL or local path, `-r` or another option that changes the source, a tool other than pip, npm, and npx, an install that names no package, packages supplied through `xargs`, an environment assignment before the install (it can redirect the index), and text the hook cannot parse. The system shall not resolve versions and shall not rewrite the command, because the hook can only allow or block the command it was given. R-1.7 does not apply to the hook.

**R-G-6 (fail closed).** If the hook cannot reach a decision, the system shall exit 2. That includes: an unreadable payload, a payload that does not close within the stdin timeout, a command that cannot be parsed, a policy, seal key, or snapshot error, an audit log that cannot be written, and a decision that does not finish within the hook deadline. When `tool_input.command` is missing or not a string, the system shall exit 2 for any install found in the payload, because it cannot know what will run.

**R-G-7 (non-install).** When the command contains no install, the system shall exit 0, shall call no verdict, shall write nothing to the audit log, and shall write nothing to stdout or stderr. This is the v1 behavior and it is unchanged. A setup failure on a non-install command does not change the exit code, because the hook does not load the pipeline for it. When the command contains an install and the pipeline cannot load or build, the system shall exit 2 (P-G-3).

**R-G-8 (exit codes and streams).** The hook shall exit with 0 or 2 only. Exit 0 is reached only through R-G-2 or R-G-7. The hook shall write nothing to stdout.

**R-G-9 (hook config).** The hook description in `.kiro/hooks/block-agent-installs.json` shall state the verdict behavior of R-G-2 to R-G-5. The packaged copy at `src/slopseal/hooks/block-agent-installs.json` shall stay identical to it (R-1.9). The `sh -c` wrapper that maps an exit code other than 0 or 2 to exit 2 shall stay.

**R-G-10 (untrusted metadata).** The system shall treat the text of a verdict reason as data. The hook shall write it as a JSON string value, never as prose that the agent could read as an instruction, and shall cap its length.

**R-G-12 (depth-1 transitive check). Not implemented. Planned for seal-v2 Phase 4.** When the hook or the PATH shim verifies a pinned install that passes R-G-1 to R-G-4, the system shall also check the direct dependencies of that exact version, one level deep, with the same L1 checks, and shall block the install if a dependency fails a check. Until Phase 4 ships this requirement, the hook and the shim do not check transitive dependencies, and T16 is open. This wording is provisional. Phase 4 writes the design and the properties before any code. R-G-4 is unchanged.

**R-G-11 (one count per install across layers).** When the hook and the PATH shim both verify the same exact package and version, the rate limit (R-4.7) shall count that install once. The hook always counts its own attempt. When the hook allows a package, it leaves one credit for that package and version. A shim attempt for the same package and version consumes one credit and does not count again, and the shim still runs the verdict pipeline. A credit expires after the 60-second window. A shim run after that window counts as a new install. The install key is the ecosystem, the normalized name, and the exact version. The shim cannot see the hook's command ID, because the hook payload has no ID that reaches the shim. This refines R-4.7 for the one case where a single install produces two attempts. The limit of 10 per minute (`max_installs_per_minute`) is unchanged. Fail closed: an unreadable rate-limit state still blocks (R-4.7).

## 2. Contract Check (Phase 2, not implemented)

**Purpose.** In live mode the registries do not publish exported symbols, so `exports()` returns nothing and every intent check blocks (R-Q-2). The Contract Check reads the exports from the artifact itself, statically, so that an intent check can answer PRESENT, ABSENT, or UNKNOWN. Offline mode is unchanged: it still reads the checksummed snapshot.

**Status.** Nothing in this section is implemented. No document may describe it as working before Phase 2 ships.

Terms used below:

- **Artifact**: the file the registry serves for one exact version. For PyPI, one wheel. For npm, the tarball.
- **Contract**: the set of export names read from an artifact. A contract is **complete** only when every file that could add an export was read and resolved. A contract that is not complete is never used to say a symbol is absent.
- **Intent check result**: PRESENT, ABSENT, or UNKNOWN (R-C-5).
- **Typed reason**: the label an UNKNOWN carries. It is one of seven: `sdist_only`, `dynamic_exports`, `limit`, `parse_error`, `network`, `no_digest`, `not_in_snapshot`. Each reason has one meaning. `parse_error` means the artifact's content could not be read. `network` means the download or metadata request failed, timed out, was refused, or was redirected to a host outside the allowlist. `no_digest` means the registry published no usable digest. `not_in_snapshot` means the offline snapshot does not cover the package or version. No cause is reported under another reason's label. `dynamic_exports` means a statement that can change an export is not one of the modelled forms of the completeness rule (section 2).
- **Names**: the contract holds each export under two forms. The qualified form is `module.symbol` (for PyPI the dotted module path, for npm the import specifier). The bare form is the symbol alone, for symbols exported at the top level of the package. Each module's dotted path is also an export name.

**R-C-1 (static only, digest verified).** When the Contract Check needs the exports of an exact version in live mode, the system shall download the artifact the registry names for that version into a private temporary directory, verify its digest against the digest the registry published for that file, and only then open it. The system shall read the artifact statically. The system shall not import, execute, or run any code from the artifact, and shall not run an install script, a hook, or a build step. The digest is read as follows:

- PyPI: the `sha256` value in `urls[].digests` of the chosen file.
- npm: `dist.integrity`, a Subresource Integrity string. The system shall use the algorithm named in the string and shall not assume sha256. It accepts `sha512`, `sha384`, and `sha256`. When the string lists several, it uses the strongest.

If the registry publishes no usable digest, the system shall return UNKNOWN with reason `no_digest`. That covers a missing digest, an npm version with only the sha1 `shasum`, an unsupported algorithm, and a malformed value. The system shall not trust sha1. If the computed digest differs from the published digest, the system shall return BLOCK (check `contract_digest`, level HARD_BLOCK), never UNKNOWN (T23). The artifact URL shall use https and a host on the allowlist for the ecosystem (`files.pythonhosted.org` for PyPI, `registry.npmjs.org` for npm), including after a redirect. Any other host is UNKNOWN with reason `network`.

**Completeness rule (opt-in; applies to R-C-2, R-C-3, and R-C-5).** An extraction is complete only when every statement that can define or change an export matches a form this spec models. Any statement that writes to exports and is not modelled gives UNKNOWN with reason `dynamic_exports`. Over-flagging costs coverage only. Under-flagging can give a false ABSENT, which stops the phase. The modelled forms are:

- Python: a top-level `def`, `class`, simple name assignment (`name = expr`, `name: type = expr`, and chained `a = b = expr` with plain names), an import binding, and a literal `__all__`.
- ESM: `export { ... }` (with or without `from "<relative path>"`), `export const`, `let`, `var`, `function`, or `class`, `export default`, and `export * from "<relative path>"`, resolved one hop.
- CommonJS: `exports.x = ...`, `module.exports.x = ...`, and `module.exports = { ... }` whose entries are plain keys or shorthand keys. `Object.defineProperty(exports, "__esModule", ...)` is ignored.

Everything else that touches exports gives UNKNOWN.

**R-C-2 (Python exports).** When the artifact is for PyPI, the system shall use a wheel. If the version has only an sdist, the system shall return UNKNOWN with reason `sdist_only` and shall not download the sdist. When several wheels exist, the system shall choose a `none-any` wheel, and otherwise the first wheel filename in ascending byte order. The system shall find importable modules from the wheel's `RECORD` file and its top-level layout, and shall ignore `*.dist-info/` and `*.data/` entries other than purelib and platlib content. A wheel with no `RECORD`, or with a layout the system does not handle, is UNKNOWN with reason `parse_error`. The system shall parse each `.py` and `.pyi` file with `ast` and shall collect, per module, the union of two sets:

- Set A: the names in `__all__`, when `__all__` is a literal list or tuple of strings. A later `__all__ += [...]`, `__all__.extend([...])`, or `__all__.append("x")` with literal strings adds to it.
- Set B: the public top-level names bound by modelled forms: `def`, `async def`, `class`, simple name assignments, and `import` and `from ... import ... [as ...]` bindings (the bound name is the alias, and `import a.b` binds `a`). A name that starts with an underscore is not in set B. The bindings above count inside module-level `if` and `try` blocks. Every branch counts: the `if`, `elif`, and `else` bodies, and the `try`, `except`, `else`, and `finally` bodies. Nested `if` and `try` blocks are walked the same way. The names from every branch are unioned, so a branch that is never taken can add a name. That can only cause a wrong PRESENT, which is reported. It cannot cause a false ABSENT. A module-level `for`, `with`, or `while` block, and a tuple target at module level, are unmodelled and give UNKNOWN (`dynamic_exports`). That is the setting for the first run. The owner may model them later.

A name in set A is exported even when it starts with an underscore.

The system shall follow `from .x import y` re-exports one hop, and `from .x import *` by reading the exports of `x` once. A star import whose target is outside the artifact, or a second hop, makes the result UNKNOWN with reason `dynamic_exports`.

The Python completeness check walks the whole file, including function bodies, and gives UNKNOWN with reason `dynamic_exports` when it finds any of the following. A reference to `exec`, `eval`, `setattr`, `globals`, `vars`, `sys.modules`, or `__dict__` counts as a reference, not only as a write, because aliasing is a write (Q1). A `global` statement. A `del` of a module name. A module-level `def __getattr__` or `def __dir__`. A `for`, `with`, or `while` block at module level, or a tuple target at module level. An augmented assignment to a module name. A non-literal change to `__all__`: a computed value, a comprehension, or `+=`, `extend`, or `append` with a non-literal argument. A file that does not parse is UNKNOWN with reason `parse_error`. A name in the contract longer than 256 characters, or containing whitespace or a control character, is UNKNOWN with reason `parse_error`.

**False-PRESENT risk of the union (documented, not a stop).** A name in set A or set B can be reported PRESENT when the module does not bind it at run time. The example is a name in `__all__` that the module never defines, or a public import inside an `if` block whose branch never runs. A wrong PRESENT is reported and does not stop the phase (P-C-4). Deleting a name is UNKNOWN under the completeness check, so a deleted name no longer adds to this risk. A false ABSENT needs a name that is bound at run time and is in neither set. The completeness check is designed to make that rare.

**R-C-3 (npm exports).** When the artifact is for npm, the system shall read `package.json` from the tarball and use the fields `exports`, `main`, `module`, and `types`. Entry files come from `exports` (every entry leaf that is JavaScript, and every `types` leaf that is a declaration file), then from `module`, `main`, or `types` when `exports` is absent, then `index.js` as Node does. The system shall check each entry file with the completeness rule above. The following give UNKNOWN with reason `dynamic_exports`:

- `module.exports = <anything that is not a plain object literal>`, including an identifier, a function, a class, a `new` expression, and a call (Q2, Q3). The system does not track member writes after such an assignment.
- An unnamed export of any kind (Q3).
- A reference to `exports` or `module` in any other form, including a `typeof module` check and a reassignment of `exports`.
- `Object.defineProperty(exports, ...)` with any name other than `__esModule`, `Object.assign(module.exports, ...)`, and bundler or compiler helpers (`__export(`, `__exportStar(`, `__reExport(`, `__createBinding(`) (Q5).
- A computed key, a spread, or a method shorthand inside a `module.exports` literal.
- `export * from` a bare package name, or a star export from a second hop.

In a `.d.ts` file, `export = <anything>` gives UNKNOWN with reason `dynamic_exports` (Q3). The declarations `export declare`, `export function`, `export const`, `export let`, `export var`, `export class`, `export interface`, `export type`, `export enum`, and `export namespace`, plus `export { a as b }` and `export default`, are modelled.

The name `default` is reserved (Q4). `export default` and `exports.default =` add it. No other rule adds it. A claim on `default` is PRESENT when it is listed, and ABSENT only when the extraction is complete and it is not listed.

When a package resolves to more than one entry point (for example an `import` and a `require` entry), a symbol is PRESENT when it is in any complete entry point. It is ABSENT only when every resolved entry point is complete and none lists it. Otherwise it is UNKNOWN with reason `dynamic_exports`.

A file the system cannot read as text, or a `package.json` that is not valid JSON, is UNKNOWN with reason `parse_error`. The scan removes comments and string contents first, so an export written inside a comment or a string is not counted. A tokenizer that cannot finish is UNKNOWN with reason `parse_error`.

**R-C-4 (resource limits and archive safety).** The system shall enforce these limits per package: 50 MB compressed, 200 MB expanded (counted after decompression), 5,000 archive members, and 10 seconds of wall time for the extractor. A limit that is reached returns UNKNOWN with reason `limit`. Before it reads any member, the system shall reject the artifact if a member name is absolute, has a `..` segment, contains a NUL byte, or repeats another member's name, or if a member is a symlink, a hardlink, a device, or a fifo. The rejection returns UNKNOWN with reason `parse_error`. The system shall not write archive members to disk. The system shall run the extractor in a subprocess with an empty environment, the Python interpreter in isolated mode, the temporary directory as its working directory, and operating-system limits on CPU time, address space, file size, and open files, with core dumps off. This is POSIX only. Windows is out of scope. If the operating system limits cannot be set, the result is UNKNOWN with reason `limit`.

**R-C-5 (three-valued result).** The system shall report an intent check against a contract as one of three values:

- PRESENT, only when the contract is complete and the symbol is in it.
- ABSENT, only when the contract is complete and the symbol is not in it.
- UNKNOWN, in every other case: a limit, a statement the completeness rule does not model, a file that does not parse, an artifact without a wheel, no usable digest, or an error getting the data. UNKNOWN carries one typed reason, one of the seven in the glossary.

An UNKNOWN shall give BLOCK (exit 1, check `api_surface`, and the reason names the typed reason). It shall never give ALLOW and shall never give QUARANTINE. Only ABSENT gives QUARANTINE (exit 75, `mismatch_type: api_absent`, R-Q-1). A symbol that is in an incomplete contract is UNKNOWN, not PRESENT. This keeps v1 R-Q-2 and P-FC-3 as written. The offline snapshot uses the same three values. A package or version the snapshot does not cover is UNKNOWN with reason `not_in_snapshot`.

**R-C-6 (cache).** The system shall cache each complete contract in `contracts/` under the state directory (default `.slopseal/contracts/`). The cache key is the verified registry digest of the artifact, written as `<algorithm>-<hex>`, and never the URL. For PyPI the key is the sha256 digest. For npm it is the sha512 digest the registry published, because the registry publishes no sha256 and a sha256 key would need the download that the cache exists to avoid. The system shall check that the key is a known algorithm followed by lowercase hexadecimal before it uses the key as a file name. Each entry shall store the key, the extractor version, the export names, and a SHA-256 hash of those fields. A cache hit shall need no download and shall return within 100 ms, measured from the point where the digest is known. The system shall discard an entry, and treat the lookup as a miss, if the stored hash does not match its content, if the key does not match the file name, if the extractor version differs, or if the file cannot be parsed. The system shall store only complete contracts. It shall never store UNKNOWN or a digest mismatch. It shall write an entry only after the artifact has been downloaded and its digest has been verified against the published digest (R-C-1). A download that fails verification leaves no entry, and no entry is written before verification. This applies to the npm key (sha512) as to the PyPI key (sha256).

**R-C-7 (Contract Diff).** When an intent check is ABSENT, the system shall add the contract diff to the QUARANTINE payload: the claimed symbol (`declared_api`), the real exports (`found_apis`), and, for each miss, the nearest real symbol. The nearest real symbol is the export with the smallest Levenshtein distance to the claimed symbol, with ties broken by ascending byte order. It is written as the `missing_evidence` entry `nearest_real_symbol:<claimed>=><nearest>`, and omitted when the contract has no exports. `found_apis` is sorted and capped, and a cap that cuts it adds the entry `found_apis_truncated`. The payload shall not include a confidence number or any other number. The payload keeps exactly the field set of R-Q-3 (P-SM-4). This applies to offline and live results alike.

**R-C-8 (wiring).** In live mode, the registry adapter shall obtain exports from the Contract Check. In offline mode it shall keep reading the snapshot, and the snapshot and its checksums shall not change. The Contract Check shall run only when an intent declares an `expected_api`, so an install without an intent downloads no artifact. The install hook and the PATH shim pass no intent and shall not run it. The only network use shall be the registry metadata request and the artifact download. For each version in the snapshot, a contract built from an artifact made from that version's snapshot data shall give the same answers as the snapshot (see design, section 2.9).

**R-C-9 (escalated retry).** When a retry meets an escalated quarantine and the contract for the package is UNKNOWN, the system shall return BLOCK (exit 1, check `api_surface`, typed reason), not exit 75 with `mismatch_type: api_absent`. The quarantine state and its escalation artifact are written as before. Only the returned decision changes. This corrects the v1 behavior at `_escalated_again`, which labels an unknown contract as `api_absent`.

### Supersedes

- v1 `design.md` section 11: "It does not verify packages." This no longer holds for verifiable installs.
- v1 `THREAT_MODEL.md` T11: "The hook does not verify packages." Same.
- v1 `design.md` section 6, step 4 and `requirements.md` R-Q-2 are unchanged. R-C-5 keeps "unknown exports give BLOCK" and adds the typed reason.
- v1 `src/slopseal/registry/live.py` states that exports are not published and the API-surface check is always unknown. After Phase 2 that holds only for artifacts the Contract Check cannot complete.

Both v1 statements are kept as written. `.kiro/specs/seal/design.md` section 11 carries a dated note that marks the statement superseded for the hook. The other places listed in `design.md` section 1.9 are corrected in the Phase 1 pull request (R-G-9).
