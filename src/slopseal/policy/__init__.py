"""Policy: load the fenced TOML block from the steering file, hash it, diff two policies.

Unknown or missing keys are policy errors (exit 78). See docs/adr/0001.

Requirements: R-1.4, R-5.7.4. Design: design.md section 7.
Layer 2.
"""
