"""Three-oracle test runner.

For each `.pkt` file: load, parse the embedded `source_fw`, evaluate
through the AST interpreter, compile and execute via BPF_PROG_RUN,
compare both to the file's `expected:` block. Reports per-oracle
pass/fail with diffs.

Methodology reference: docs/F_DEVELOPMENT_METHODOLOGY.md:132-181.
"""
