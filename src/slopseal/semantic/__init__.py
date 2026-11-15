"""L2 semantic intent verification (optional, gated at milestone M1).

Holds the SemanticBackend interface and, only if the M1 gate passes, the Needle
adapter. Advisory only: output can move ALLOW to QUARANTINE and never to a block.
Package metadata is passed as data, never concatenated into instructions.

Requirements: R-3.1 .. R-3.8. Design: design.md section 12.
Layer 3. Must not import core.
"""
