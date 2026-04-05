"""Indentation-aware postlexer for Lark.

Converts leading whitespace into INDENT/DEDENT/NEWLINE tokens,
same approach as CPython's tokenizer.  Lark's built-in indenter
needs some customization for our grammar.
"""

from lark import Token
from lark.indenter import Indenter


class FwlIndenter(Indenter):
  """FWL indentation handler."""

  NL_type = "_NL"
  OPEN_PAREN_types = ["LPAR", "LSQB"]
  CLOSE_PAREN_types = ["RPAR", "RSQB"]
  INDENT_type = "_INDENT"
  DEDENT_type = "_DEDENT"
  tab_len = 2
