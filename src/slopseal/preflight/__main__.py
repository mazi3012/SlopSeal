"""Print the preflight status for an agent account (`python -m slopseal.preflight`).

Only the local checks run here. Probe checks (A5, A6, A8, A9, B1, B2) are NOT_RUN, so the status is
NOT ENFORCED until a live probe harness supplies them. This is the intended result for a host
where the probes have not been run. The command never changes the host.

Exit codes: 0 ENFORCED, 1 PARTIALLY ENFORCED, 2 NOT ENFORCED.
"""

from __future__ import annotations

import argparse
import pwd
import sys
from pathlib import Path

from slopseal.preflight.model import Status
from slopseal.preflight.runner import PreflightInputs, gather_local, run

EXIT = {Status.ENFORCED: 0, Status.PARTIALLY_ENFORCED: 1, Status.NOT_ENFORCED: 2}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m slopseal.preflight")
    parser.add_argument("--agent", required=True, help="the OS account the agent runs as")
    parser.add_argument("--service-dir", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument(
        "--pin", default=None, help="sha256 of the policy, pinned outside the agent"
    )
    args = parser.parse_args(argv)
    try:
        agent_uid = pwd.getpwnam(args.agent).pw_uid
    except KeyError:
        print(f"unknown account: {args.agent}", file=sys.stderr)
        return 2
    local = gather_local(args.agent, args.service_dir, args.policy)
    result = run(
        PreflightInputs(agent=args.agent, agent_uid=agent_uid, local=local, pinned_sha256=args.pin)
    )
    for check in result.checks:
        print(f"{check.id:<3} {check.result.value:<8} {check.title} - {check.detail}")
    print(f"status: {result.status.value}")
    print(f"reason: {result.reason}")
    return EXIT[result.status]


if __name__ == "__main__":
    sys.exit(main())
