"""Unit tests for the shim command-line parser (R-1.1, R-1.3)."""

from __future__ import annotations

import pytest

from slopseal.intercept.parse import Blocked, Install, Passthrough, parse


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["install", "tinyfmt-kit==0.4.0"], (("tinyfmt-kit", "0.4.0"),)),
        (["install", "-q", "--no-deps", "flask==3.0.0"], (("flask", "3.0.0"),)),
        (["install", "--target", "vendor", "rich==13.7.0"], (("rich", "13.7.0"),)),
        (["install", "--", "pandas==2.2.0"], (("pandas", "2.2.0"),)),
    ],
)
def test_pip_installs_parse_to_verifiable_specs(args: list[str], expected: tuple) -> None:
    result = parse("pip", args)
    assert result == Install("pypi", expected)


@pytest.mark.parametrize(
    "args",
    [
        ["install", "requests>=2.0"],
        ["install", "numpy~=1.26"],
        ["install", "flask==3.*"],
        ["install", "pkg==1.0; python_version>'3'"],
        ["install", "name===1.0"],
        ["install", "requests"],
        ["install", "requests[socks]"],
    ],
)
def test_pip_ranges_markers_and_unpinned_block(args: list[str]) -> None:
    assert isinstance(parse("pip", args), Blocked)


@pytest.mark.parametrize(
    "args",
    [
        ["install", "./local_pkg"],
        ["install", "https://example.com/pkg.tar.gz"],
        ["install", "pkg.whl"],
        ["install", "git+https://github.com/x/y.git"],
        ["install", "some/path"],
    ],
)
def test_pip_local_paths_and_urls_block(args: list[str]) -> None:
    assert isinstance(parse("pip", args), Blocked)


@pytest.mark.parametrize(
    "args",
    [
        ["install", "-r", "requirements.txt"],
        ["install", "--requirement=requirements.txt"],
        ["install", "-e", "."],
        ["install", "--index-url", "https://evil.example", "requests==2.31.0"],
        ["install", "--extra-index-url=https://evil.example", "requests==2.31.0"],
        ["install", "--no-index", "requests==2.31.0"],
    ],
)
def test_pip_index_and_requirement_flags_block(args: list[str]) -> None:
    assert isinstance(parse("pip", args), Blocked)


def test_pip_unknown_option_blocks() -> None:
    assert isinstance(parse("pip", ["install", "--some-new-flag", "requests==2.31.0"]), Blocked)


def test_pip_non_install_passes_through() -> None:
    assert parse("pip", ["list"]) == Passthrough()
    assert parse("pip", []) == Passthrough()


def test_pip_install_with_no_packages_passes_through() -> None:
    assert parse("pip", ["install", "-q"]) == Passthrough()


def test_npm_exact_pins_parse() -> None:
    assert parse("npm", ["install", "react-codemod@2.0.0"]) == Install(
        "npm", (("react-codemod", "2.0.0"),)
    )
    assert parse("npm", ["i", "@scope/pkg@1.2.3"]) == Install("npm", (("@scope/pkg", "1.2.3"),))


@pytest.mark.parametrize("spec", ["lodash", "@scope/pkg"])
def test_npm_unpinned_names_block(spec: str) -> None:
    assert isinstance(parse("npm", ["install", spec]), Blocked)


def test_npm_names_that_start_with_git_are_not_blocked() -> None:
    assert parse("npm", ["install", "git-hooks@1.0.0"]) == Install("npm", (("git-hooks", "1.0.0"),))


@pytest.mark.parametrize(
    "spec",
    [
        "^1.2.3",
        "~1.2.3",
        "react@^18",
        "file:../pkg",
        "git+https://github.com/x/y.git",
        "github:x/y",
        "https://example.com/pkg.tgz",
        "./local",
    ],
)
def test_npm_ranges_tags_and_sources_block(spec: str) -> None:
    assert isinstance(parse("npm", ["install", spec]), Blocked)


def test_npm_install_without_packages_blocks() -> None:
    assert isinstance(parse("npm", ["install"]), Blocked)


@pytest.mark.parametrize("verb", ["ci", "update", "upgrade", "install-clean"])
def test_npm_lockfile_and_update_verbs_block(verb: str) -> None:
    assert isinstance(parse("npm", [verb]), Blocked)


def test_npm_registry_redirect_blocks() -> None:
    assert isinstance(
        parse("npm", ["install", "--registry", "https://evil.example", "lodash@4.17.21"]),
        Blocked,
    )


def test_npm_non_install_passes_through() -> None:
    assert parse("npm", ["run", "build"]) == Passthrough()
    assert parse("npm", ["test"]) == Passthrough()


def test_unknown_tool_passes_through() -> None:
    assert parse("cargo", ["install", "x"]) == Passthrough()


# R-1.6: npx, npm exec, npm x, and npm init/create with an initializer are installs.


@pytest.mark.parametrize(
    ("tool", "args", "expected"),
    [
        ("npx", ["react-codeshift@1.0.0"], (("react-codeshift", "1.0.0"),)),
        ("npx", ["--yes", "tinyfmt-kit@0.4.0", "--help"], (("tinyfmt-kit", "0.4.0"),)),
        ("npx", ["--", "tinyfmt-kit@0.4.0"], (("tinyfmt-kit", "0.4.0"),)),
        ("npx", ["-p", "a@1.0.0", "a"], (("a", "1.0.0"),)),
        ("npx", ["--package=a@1.0.0", "a", "--flag"], (("a", "1.0.0"),)),
        ("npm", ["exec", "tinyfmt-kit@0.4.0"], (("tinyfmt-kit", "0.4.0"),)),
        ("npm", ["x", "@scope/pkg@1.2.3", "arg"], (("@scope/pkg", "1.2.3"),)),
        ("npm", ["exec", "--package=a@1.0.0", "--", "a"], (("a", "1.0.0"),)),
    ],
)
def test_exec_style_pins_parse_to_verifiable_specs(
    tool: str, args: list[str], expected: tuple
) -> None:
    assert parse(tool, args) == Install("npm", expected)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("npx", ["evil"]),
        ("npx", ["@scope/evil"]),
        ("npx", ["evil@^1.0.0"]),
        ("npx", ["evil@latest"]),
        ("npx", []),
        ("npx", ["--yes"]),
        ("npx", ["-c", "rm -rf ."]),
        ("npx", ["--call=echo hi"]),
        ("npx", ["--no-install", "evil@1.0.0"]),
        ("npx", ["-p", "a", "a"]),
        ("npx", ["-p", "a@1.0.0", "b"]),
        ("npx", ["-p"]),
        ("npx", ["./local@1.0.0"]),
        ("npx", ["https://example.com/x.tgz"]),
        ("npx", ["git+https://github.com/x/y.git"]),
        ("npx", ["--registry", "https://evil.example", "evil@1.0.0"]),
        ("npm", ["exec"]),
        ("npm", ["exec", "--"]),
        ("npm", ["exec", "evil"]),
        ("npm", ["exec", "--", "evil"]),
        ("npm", ["x", "evil"]),
        ("npm", ["exec", "-c", "evil@1.0.0"]),
        ("npm", ["exec", "--package=a", "--", "a@1.0.0"]),
        ("npm", ["init", "react-app"]),
        ("npm", ["init", "react-app@5.0.0"]),
        ("npm", ["create", "vite"]),
    ],
)
def test_exec_style_unverifiable_forms_block(tool: str, args: list[str]) -> None:
    assert isinstance(parse(tool, args), Blocked)


@pytest.mark.parametrize(
    "args",
    [["init", "-y"], ["init"], ["init", "--yes"]],
)
def test_npm_init_without_initializer_passes_through(args: list[str]) -> None:
    assert parse("npm", args) == Passthrough()
