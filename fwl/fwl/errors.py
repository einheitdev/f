"""Error types for the FWL compiler.

Errors carry source spans (line, column) so messages can point at the
exact location in the .fw source. Constructed once at the point of
detection, not propagated as exceptions across module boundaries.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
  """A source location: line and column, both 1-based."""
  line: int
  column: int


@dataclass(frozen=True)
class FwlError:
  """A compilation error.

  Categories:
    - syntax: produced by the parser when the input doesn't match the
      grammar.
    - semantic: produced by the analyzer (protocol guards, type checks,
      etc.).
    - codegen: produced by the emitter, e.g. when the BPF verifier
      rejects the generated program.
  """
  category: str
  message: str
  span: Span | None = None

  def format(self) -> str:
    """Format as a single-line error message."""
    if self.span is None:
      return f"error: {self.message}"
    return (
      f"error: {self.span.line}:{self.span.column}: {self.message}"
    )


class FwlException(Exception):
  """Raised when the compiler encounters an error.

  Carries one or more FwlError instances. The first error is fatal per
  the spec (FWL_V01_SPEC.md:402); the compiler does not attempt to
  recover and continue parsing.
  """

  def __init__(self, error: FwlError):
    super().__init__(error.format())
    self.error = error
