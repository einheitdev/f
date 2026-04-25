"""AST interpreter — independent oracle for the verification loop.

Walks the AST against a parsed packet (a dict of decoded fields)
and returns the XDP action the program would take. Implementation
must not share any code with the emitter beyond AST node definitions
— the whole point is independent evaluation.

Spec reference: docs/FWL_V01_SPEC.md, methodology reference:
docs/F_DEVELOPMENT_METHODOLOGY.md:307-311.
"""
