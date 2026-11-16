"""Property test for one rate-limit count per install across the hook and the shim (P-G-2).

Requirements: R-G-11, R-4.7. Property: P-G-2 (`.kiro/specs/seal-v2/properties.md`).
Hypothesis runs 500 examples per property (conftest.py profile).

The oracle is a plain counter that applies the credit rules from the spec. It does not use the
limiter's code. Each example runs real `verify_install` calls with a real RateLimiter in a
temporary state directory, so the hook layer, the shim layer, the credit file, and the audit
path are all exercised.
"""

from __future__ import annotations

import itertools
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from slopseal.audit.log import AuditLog
from slopseal.audit.seal import load_or_create_key
from slopseal.core.types import Ecosystem
from slopseal.fixtures.loader import load_snapshot
from slopseal.hooks.gate import decide
from slopseal.hooks.on_install import Detected
from slopseal.intercept.parse import Blocked, parse
from slopseal.policy.loader import load_policy
from slopseal.quarantine.rate_limit import WINDOW, Layer, RateDecision, RateLimiter
from slopseal.quarantine.state_machine import QuarantineStore, new_quarantine_id
from slopseal.registry.source import OfflineSource
from slopseal.verdict import Context, Decision, InstallRequest, Outcome, verify_install

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "src" / "slopseal" / "fixtures"
POLICY = REPO / ".kiro" / "steering" / "dependency-trust.md"
AS_OF = datetime(2026, 11, 18, tzinfo=UTC)
BASE = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
LIMIT = 10

# Installs in the offline snapshot. The first three are ALLOW. The last is BLOCK (absent).
KEYS: tuple[tuple[Ecosystem, str, str], ...] = (
    (Ecosystem.PYPI, "tinyfmt-kit", "0.4.0"),
    (Ecosystem.PYPI, "csv-parser", "1.2.0"),
    (Ecosystem.NPM, "colorkit", "2.0.1"),
    (Ecosystem.PYPI, "csv-parser-pro", "0.1.0"),
)
ALLOWED = {0, 1, 2}
# Spellings of the same install. PyPI names compare under PEP 503 (case, and runs of `-`, `_`,
# `.` are equal). npm names compare lowercase. Each layer may spell the name differently, and
# the credit must still match (R-G-11).
SPELLINGS: tuple[tuple[str, ...], ...] = (
    ("tinyfmt-kit", "Tinyfmt_Kit", "TINYFMT.KIT", "tinyfmt_kit"),
    ("csv-parser", "CSV_Parser", "csv.parser"),
    ("colorkit", "ColorKit"),
    ("csv-parser-pro", "CSV_PARSER_PRO"),
)

events = st.one_of(
    st.tuples(st.just("hook"), st.integers(0, len(KEYS) - 1), st.integers(0, 3)),
    st.tuples(st.just("shim"), st.integers(0, len(KEYS) - 1), st.integers(0, 3)),
    st.tuples(st.just("tick"), st.integers(0, 90), st.just(0)),
)


@dataclass
class Model:
    """The spec rules, written as a plain counter."""

    counted: int = 0
    credits: dict[int, list[int]] = field(default_factory=dict)

    def run(self, sequence: list[tuple[str, int, int]]) -> int:
        now = 0
        for kind, value, _spelling in sequence:
            if kind == "tick":
                now += value
                continue
            # Credits are live for 0 to 60 seconds. Keys with none left are removed.
            self.credits = {
                key: [t for t in stamps if 0 <= now - t < WINDOW.total_seconds()]
                for key, stamps in self.credits.items()
            }
            self.credits = {key: stamps for key, stamps in self.credits.items() if stamps}
            if kind == "hook":
                self.counted += 1  # the hook always counts
                if value in ALLOWED:
                    self.credits.setdefault(value, []).append(now)
            else:  # shim
                if self.credits.get(value):
                    self.credits[value].pop(0)
                    if not self.credits[value]:
                        del self.credits[value]
                else:
                    self.counted += 1
        return self.counted


class CountingLimiter(RateLimiter):
    """The real limiter, with a count of the attempts it records.

    The file keeps only attempts inside the window, so the file alone cannot give a total.
    Each attempt the limiter counts (every attempt, allowed or not) adds one here.
    """

    def __init__(self, root: Path, limit: int, clock: Callable[[], datetime]) -> None:
        super().__init__(root, limit, clock=clock)
        self.counted = 0

    def attempt(self, key: str | None = None, layer: Layer = Layer.OTHER) -> RateDecision:
        decision = super().attempt(key, layer)
        if decision.counted:
            self.counted += 1
        return decision


def _context(state: Path, clock: list[int]) -> Context:
    counter = itertools.count(1)
    return Context(
        policy=load_policy(str(POLICY)),
        source=OfflineSource(load_snapshot(FIXTURES)),
        store=QuarantineStore(state),
        log=AuditLog(state / "audit.jsonl", load_or_create_key(state)),
        now=AS_OF,
        new_id=lambda: new_quarantine_id(next(counter).to_bytes(13, "big")),
        limiter=CountingLimiter(state, LIMIT, clock=lambda: BASE + timedelta(seconds=clock[0])),
    )


def _counted(context: Context) -> int:
    limiter = context.limiter
    assert isinstance(limiter, CountingLimiter)
    return limiter.counted


@given(sequence=st.lists(events, max_size=LIMIT))
def test_p_g_2_one_install_counts_once_across_layers(
    sequence: list[tuple[str, int, int]],
) -> None:
    """P-G-2: the code's count equals the model's count for any event sequence.

    At most LIMIT events run, so no call is blocked by the limit itself. The oracle does not
    depend on the order the verdicts come back in.
    """
    expected = Model().run(sequence)
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = [0]
        context = _context(state, clock)
        for kind, value, spelling in sequence:
            if kind == "tick":
                clock[0] += value
                continue
            ecosystem, _name, version = KEYS[value]
            names = SPELLINGS[value]
            name = names[spelling % len(names)]
            layer = Layer.HOOK if kind == "hook" else Layer.SHIM
            decision = verify_install(
                InstallRequest(ecosystem, name, version, layer=layer), context
            )
            if value in ALLOWED:
                assert decision.outcome is Outcome.ALLOW, decision.reason
            else:
                assert decision.outcome is Outcome.BLOCK
        assert _counted(context) == expected


def test_p_g_2_spelling_variants_share_one_credit() -> None:
    """A hook call spelled `Tinyfmt_Kit` and a shim call spelled `tinyfmt-kit` are one install."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = _context(state, [0])
        hook = InstallRequest(Ecosystem.PYPI, "Tinyfmt_Kit", "0.4.0", layer=Layer.HOOK)
        shim = InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0", layer=Layer.SHIM)
        assert verify_install(hook, context).outcome is Outcome.ALLOW
        assert verify_install(shim, context).outcome is Outcome.ALLOW
        assert _counted(context) == 1


def test_p_g_2_unpinned_install_is_refused_before_a_credit_is_used() -> None:
    """An unpinned install is refused by the hook and the shim before the limiter runs.

    The refusal must not use the credit. The next pinned shim call for the same package still
    consumes the credit and counts nothing. The credit is what keeps the count at 1.
    """
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = _context(state, [0])
        pinned_hook = InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0", layer=Layer.HOOK)
        assert verify_install(pinned_hook, context).outcome is Outcome.ALLOW
        assert _counted(context) == 1

        verified: list[InstallRequest] = []

        def verify(request: InstallRequest, _context: object) -> Decision:
            verified.append(request)
            return verify_install(request, context)

        # The hook: an unpinned command is a problem before any verdict is requested.
        result = decide(
            [Detected("pip", ("install", "tinyfmt-kit"))],
            build=lambda: context,
            verify=verify,
        )
        assert result.exit_code == 2
        assert verified == []
        # The shim: parse refuses the unpinned spec in offline mode, before the limiter.
        assert isinstance(parse("pip", ["install", "tinyfmt-kit"], allow_unpinned=False), Blocked)
        assert _counted(context) == 1

        # The credit survives both refusals. The pinned shim call consumes it, counts nothing.
        pinned_shim = InstallRequest(Ecosystem.PYPI, "tinyfmt-kit", "0.4.0", layer=Layer.SHIM)
        assert verify_install(pinned_shim, context).outcome is Outcome.ALLOW
        assert _counted(context) == 1


def test_p_g_2_hook_then_shim_is_one_count() -> None:
    """The case from the bug report: one install verified by both layers counts once."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = [0]
        context = _context(state, clock)
        request = {"ecosystem": Ecosystem.PYPI, "package": "tinyfmt-kit", "version": "0.4.0"}
        assert verify_install(InstallRequest(**request, layer=Layer.HOOK), context).outcome is (
            Outcome.ALLOW
        )
        shim = verify_install(InstallRequest(**request, layer=Layer.SHIM), context)
        assert shim.outcome is Outcome.ALLOW
        assert _counted(context) == 1


def test_p_g_2_shim_still_verifies_after_a_credit_is_consumed() -> None:
    """The shim verdict is not skipped. Only the count is. A BLOCKED install still blocks."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = _context(state, [0])
        blocked = {"ecosystem": Ecosystem.PYPI, "package": "csv-parser-pro", "version": "0.1.0"}
        decision = verify_install(InstallRequest(**blocked, layer=Layer.SHIM), context)
        assert decision.outcome is Outcome.BLOCK
        assert _counted(context) == 1  # no credit existed, so the shim counted it


def test_p_g_2_credit_expires_after_the_window() -> None:
    """A hook allow with no shim run counts once. A shim run after the window counts again."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = [0]
        context = _context(state, clock)
        request = {"ecosystem": Ecosystem.NPM, "package": "colorkit", "version": "2.0.1"}
        verify_install(InstallRequest(**request, layer=Layer.HOOK), context)
        clock[0] = int(WINDOW.total_seconds()) + 1
        verify_install(InstallRequest(**request, layer=Layer.SHIM), context)
        assert _counted(context) == 2


def test_p_g_2_a_credit_stamped_in_the_future_is_not_used() -> None:
    """If the clock moves back, a credit is dropped. It must not stay alive and skip a count."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = [0]
        context = _context(state, clock)
        request = {"ecosystem": Ecosystem.NPM, "package": "colorkit", "version": "2.0.1"}
        clock[0] = 30
        verify_install(InstallRequest(**request, layer=Layer.HOOK), context)
        clock[0] = 0  # the clock now reads earlier than the credit
        verify_install(InstallRequest(**request, layer=Layer.SHIM), context)
        assert _counted(context) == 2


def test_p_g_2_shim_passes_on_a_full_window_when_a_credit_exists() -> None:
    """A full window does not block a shim call that the hook already counted."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        clock = [0]
        context = _context(state, clock)
        allowed = {"ecosystem": Ecosystem.PYPI, "package": "tinyfmt-kit", "version": "0.4.0"}
        for _ in range(LIMIT - 1):
            verify_install(InstallRequest(**allowed, layer=Layer.OTHER), context)
        verify_install(InstallRequest(**allowed, layer=Layer.HOOK), context)  # the 10th count
        shim = verify_install(InstallRequest(**allowed, layer=Layer.SHIM), context)
        assert shim.outcome is Outcome.ALLOW
        assert _counted(context) == LIMIT
        over = verify_install(InstallRequest(**allowed, layer=Layer.SHIM), context)
        assert over.outcome is Outcome.BLOCK  # the next uncredited attempt is over the limit


def test_p_g_2_unreadable_state_blocks_both_layers() -> None:
    """Fail closed: a corrupt rate-limit file blocks the hook and the shim."""
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp)
        context = _context(state, [0])
        (state / "ratelimit.json").write_text("{not json", encoding="utf-8")
        request = {"ecosystem": Ecosystem.PYPI, "package": "tinyfmt-kit", "version": "0.4.0"}
        for layer in (Layer.HOOK, Layer.SHIM):
            decision = verify_install(InstallRequest(**request, layer=layer), context)
            assert decision.outcome is Outcome.BLOCK
            assert decision.violation is not None
            assert decision.violation.check == "rate_limit"
