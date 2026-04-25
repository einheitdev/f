"""BPF_PROG_RUN harness — pure Python via ctypes against libbpf.

Given BPF C source and a packet bytes blob, compiles via
`clang -target bpf`, loads via bpf(BPF_PROG_LOAD), runs via
bpf(BPF_PROG_RUN), and returns the XDP action.

Requires CAP_BPF (or root) on a Linux host with libbpf installed.
"""
