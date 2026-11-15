"""Install interception: PATH shim and the verify_install API.

Thin callers only. No check logic lives here. Unparseable install commands block.

Requirements: R-1.1, R-1.3, R-1.5. Design: design.md section 11.
Layer 5 (may import verdict and below).
"""
