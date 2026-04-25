"""`fwl` command-line interface.

Subcommands:
  parse <file>       Parse only; print AST.
  check <file>       Parse + semantic check.
  compile <file>     Full compile to .bpf.c (and .bpf.o via clang).
  interpret <file> <pkt>   AST interpreter against a test packet.
  test <dir>         Run a corpus directory through the verification
                     loop.
  version            Print version.
"""


def main():
  """Entry point for the `fwl` console script."""
  raise NotImplementedError("CLI not implemented yet")
