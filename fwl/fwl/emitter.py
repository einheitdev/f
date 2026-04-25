"""BPF C code generator.

Given an analyzed AST, emits a C source string that clang compiles to
a verifier-accepted XDP program. Bounds checks at every layer; IPv4
IHL handled correctly; TCP/UDP ports in host byte order.
"""
