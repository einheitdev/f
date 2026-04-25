"""Semantic analysis: protocol guards, types, default placement.

Walks the AST and rejects programs that parse but violate v0.1
semantics. Per spec FWL_V01_SPEC.md:382-400, errors are fatal — first
error encountered is reported and analysis stops.
"""
