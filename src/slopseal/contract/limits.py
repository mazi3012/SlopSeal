"""Fixed safety ceilings of the Contract Check (design section 2.12).

These are resource limits, not trust thresholds. A later policy section may lower them. Policy
may never raise them, and a floor in policy/invariants.py must enforce that when such a section
exists. Each value is marked:

- owner: taken from the brief.
- proposed: chosen by the design. The owner may change it before the code lands.

Requirements: R-C-4, R-C-6. Layer 0.
"""

from __future__ import annotations

MB = 1024 * 1024

# owner
MAX_COMPRESSED_BYTES = 50 * MB
MAX_EXPANDED_BYTES = 200 * MB
MAX_MEMBERS = 5000
WORKER_WALL_SECONDS = 10.0
CACHE_HIT_MILLISECONDS = 100

# proposed
DOWNLOAD_WALL_SECONDS = 30.0
SOURCE_FILE_MAX_BYTES = 5 * MB
MAX_CONTRACT_NAMES = 100_000
WORKER_OUTPUT_MAX_BYTES = 8 * MB
WORKER_ADDRESS_SPACE_BYTES = 1024 * MB
WORKER_OPEN_FILES = 16
FOUND_APIS_MAX = 200
DETAIL_MAX_CHARS = 200

# from the spec (R-C-2): a contract name is at most this many characters.
MAX_NAME_LENGTH = 256
