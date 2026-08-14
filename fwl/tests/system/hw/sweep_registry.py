"""What each hardware scenario claims, and how to break that claim.

One entry per scenario in tests/system/hw. The fields are a contract:

  subject   what the scenario exists to catch, in the product's terms.
  plants    the defect, planted on purpose. Running the scenario with it
            in place MUST turn the scenario red; a scenario that stays
            green is vacuous and is reported, not deleted.
  residual  the part of the subject a plant does not reach. Most often
            this is a property of the DAEMON rather than of a policy or
            the environment, and reaching it needs a mutated fd binary
            rather than a mutated input.
  declared  set instead of `plants` when the subject genuinely cannot be
            broken on this bench. Declared scenarios are counted and
            named separately — never folded into pass or fail.
  witness_note  why a weak witness (a counter, a promiscuous sniffer) is
            the right one here. Required for any scenario whose
            strongest witness is rank <= 2, because six of the nine NAT
            scenarios keep the sniffer legitimately and three did not,
            and nothing in the files said which was which.

Two rules the plants follow, learned from the defects that motivated
this file:

  Prefer breaking the ACTION over breaking the counter. A counter is the
  cheapest witness to satisfy; the claim that matters is the disposition
  on the wire, so a plant that leaves every counter correct and changes
  only what reaches the far side puts the load on the witness that was
  wrong before.

  Never plant into the smoke policy. sweep_lib.rewrite_argv only touches
  a compile into v-hw-<tag>-<pid>, so hw::restore_smoke — which runs
  from the EXIT trap of every scenario — always recompiles the
  operator's real /etc/f/rules.fw unmodified.
"""
import os
from sweep_lib import DeployCmd, FileSub, PolicySub, Plant, Scenario
from sweep_lib import UnitDropIn

PIN = '/sys/fs/bpf/f'
RECV_IF = os.environ.get('RECV_IF', 'enp1s0f1')

def _s(name, subject, plants=(), declared='', witness_note='',
       timeout_s=600):
  return Scenario(name=name, subject=subject, plants=tuple(plants),
                  declared=declared, witness_note=witness_note,
                  timeout_s=timeout_s)

def _p(ident, defect, steps, residual='', verify=''):
  return Plant(ident=ident, defect=defect, steps=tuple(steps),
               residual=residual, verify=verify)

# Turning masquerade off without removing it: the rule stays, its
# condition stops matching any test address. The policy still compiles
# and still carries a NAT program, so what changes is only whether the
# source was translated.
def _masq_off(tag='*'):
  return PolicySub(tag=tag, regex=True,
                   find=r'^masquerade if .*$',
                   repl='masquerade if pkt.src_ip == 10.99.199.199')

SCENARIOS = {s.name: s for s in [

    # ---------------- Layer 1: the construct matrix ----------------
    _s('l1_01_proto_port_cidr',
       'the proto/port/CIDR predicates admit exactly the frames they '
       'name, and drop the rest',
       [_p('port80-allow-misses',
           'the allow rule for tcp/80 is written for the wrong port, so '
           'traffic the policy admits is dropped at the wire while every '
           'counter still reads correctly',
           [PolicySub(tag='l1-01',
                      find='allow if pkt.proto == tcp and pkt.dst_port == 80',
                      repl='allow if pkt.proto == tcp and pkt.dst_port == 81')])],
       witness_note='disposition only; no delivery is claimed, so the '
                    'AF_PACKET tap after XDP is the right witness',
       timeout_s=240),

    _s('l1_02_default_action',
       'the `default` verdict is what an unmatched frame gets',
       [_p('default-drop-is-allow',
           'the deny-by-default policy silently defaults to allow',
           [PolicySub(tag='l1-02a', find='default drop',
                      repl='default allow')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_03_tcp_flags',
       'TCP flag predicates distinguish SYN from SYN+ACK from ACK',
       [_p('syn-drop-eats-synack',
           'the SYN drop loses its `not ack` qualifier, so it also eats '
           'the SYN+ACK of every returning handshake',
           [PolicySub(tag='l1-03',
                      find='drop if pkt.proto == tcp and pkt.tcp.syn and '
                           'not pkt.tcp.ack',
                      repl='drop if pkt.proto == tcp and pkt.tcp.syn')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_04_icmp',
       'ICMP type matching selects one type and not its neighbours',
       [_p('icmp-drop-off-by-one',
           'the ICMP redirect drop is written for type 6, so redirects '
           'pass while the counter that names them still ticks',
           [PolicySub(tag='l1-04',
                      find='drop if pkt.proto == icmp and pkt.icmp.type == 5',
                      repl='drop if pkt.proto == icmp and pkt.icmp.type == 6')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_05_vlan',
       '802.1Q tags survive to XDP and vlan_id matching works on them',
       [_p('vlan-drop-off-by-one',
           'the vlan 100 drop is written for 101: tagged frames the '
           'policy blocks reach the far side',
           [PolicySub(tag='l1-05', find='drop if pkt.vlan_id == 100',
                      repl='drop if pkt.vlan_id == 101')],
           residual='the bench hazard this test also guards — the i350 '
                    'stripping tags in hardware before XDP — is planted '
                    'by `ethtool -K rxvlan on`; that variant is not run '
                    'here because the BLOCKED branch already fails on it')],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_06_rate_limit',
       'a rate_limit modifier actually caps a flood, per bucket',
       [_p('budget-effectively-infinite',
           'the rate limit is set so high it never bites, so a flood '
           'passes in full',
           [PolicySub(tag='l1-06', find='rate_limit(50, per=src_ip)',
                      repl='rate_limit(1000000, per=src_ip)')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_07_count',
       'counters count the frames they name, exactly, and monotonically '
       'across rounds',
       [_p('counter-matches-nothing',
           'a counter predicate names a subnet no test frame is in, so '
           'it stays at zero while traffic flows',
           [PolicySub(tag='l1-07',
                      find='count all_test if pkt.src_ip in 10.99.8.0/24',
                      repl='count all_test if pkt.src_ip in 10.99.9.0/24')])],
       witness_note='the subject IS the counter, so the counter is the '
                    'right and only witness',
       timeout_s=240),

    _s('l1_08_log',
       'a `log` action emits one ring-buffer record per matching frame, '
       'and `sample=` thins it',
       [_p('log-matches-nothing',
           'the log rule names a port nothing sends to, so the ring stays '
           'empty while traffic flows',
           [PolicySub(tag='l1-08a',
                      find='log if pkt.proto == udp and pkt.dst_port == 7777',
                      repl='log if pkt.proto == udp and pkt.dst_port == 7778')],
           residual='the sample= leg (l1-08b) is not planted in this '
                    'sweep; a second plant would target sample=10 -> 1')],
       witness_note='the ring buffer is the subject; nothing on the wire '
                    'reports it',
       timeout_s=240),

    _s('l1_09_geoip',
       'the geoip production path end to end: compile emits the trie '
       'data, fd populates the pinned LPM trie, the datapath matches it',
       [_p('trie-data-wrong-prefix',
           'the geoip data names a prefix one octet away from the traffic, '
           'so the trie fd loaded matches nothing — the shape a stale or '
           'mis-generated country file has',
           [PolicySub(tag='l1-09', flag='--geoip', find='10.99.77.0/24',
                      repl='10.99.78.0/24')])],
       witness_note='disposition only',
       timeout_s=300),

    _s('l1_10_conntrack',
       'conntrack state: a reply to a flow this box saw open reads '
       'ESTABLISHED and is admitted, an unsolicited one is not',
       [_p('allow-keys-on-new',
           'the stateful allow reads NEW instead of ESTABLISHED, so every '
           'reply to a tracked flow is dropped',
           [PolicySub(tag='l1-10',
                      find='allow if conntrack(pkt).state == established',
                      repl='allow if conntrack(pkt).state == new')])],
       witness_note='disposition only',
       timeout_s=300),

    _s('l1_11_ipv6_fields',
       'IPv6 addresses and prefixes match, and a v6 rule does not leak '
       'into v4 traffic',
       [_p('v6-drop-wrong-prefix',
           'the v6 blocklist prefix is one nibble out, so blocked v6 '
           'traffic passes',
           [PolicySub(tag='l1-11',
                      find='drop if pkt.src_ip6 in 2001:db8:99:dd::/64',
                      repl='drop if pkt.src_ip6 in 2001:db8:99:ef::/64')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_12_icmpv6',
       'ICMPv6 type matching is distinct from ICMPv4 type matching',
       [_p('icmp6-drop-off-by-one',
           'the ICMPv6 redirect drop names type 136, so redirects pass',
           [PolicySub(tag='l1-12',
                      find='drop if pkt.proto == icmp6 and pkt.icmp6.type == 137',
                      repl='drop if pkt.proto == icmp6 and pkt.icmp6.type == 136')])],
       witness_note='disposition only',
       timeout_s=240),

    _s('l1_13_ipv6_activation',
       'a policy with no v6 rule does not parse v6 (it reaches the '
       'default), and one with a v6 rule does',
       [_p('v6-prefix-misses',
           'the activating v6 rule names a prefix the traffic is not in, '
           'so v6 frames are parsed and matched by nothing',
           [PolicySub(tag='l1-13b', find='2001:db8:99::/48',
                      repl='2001:db8:98::/48')])],
       witness_note='disposition only',
       timeout_s=300),

    # ---------------- Layer 2: NAT, redirect, the dogfood ----------
    _s('l2_01_zone_redirect',
       'a `redirect` really transmits — the frame leaves the DUT on '
       'copper via ndo_xdp_xmit, which no software counter can fake',
       [_p('redirect-becomes-allow',
           'the redirect degrades to a plain allow: the rule still fires '
           'and its counter still climbs, but nothing is transmitted',
           [PolicySub(tag='l2-01',
                      find='redirect to t if pkt.src_ip == 10.99.30.5',
                      repl='allow if pkt.src_ip == 10.99.30.5')])],
       timeout_s=240),

    _s('l2_02_snat',
       'snat rewrites the source and the far side accepts the result — '
       'the acceptance leg uses a real non-promiscuous host',
       [_p('snat-to-wrong-address',
           'the translation writes an address that is not the box\'s, so '
           'the rewrite happens and the flow goes nowhere',
           [PolicySub(regex=True, find=r'snat to \S+ if',
                      repl='snat to 10.99.244.244 if')])],
       timeout_s=420),

    _s('l2_03_masquerade',
       'masquerade + redirect is a working gateway: the far side accepts '
       'the connection AND its own kernel reports the masquerade address '
       'as the peer',
       [_p('masquerade-does-not-match',
           'the masquerade rule stops matching the guest, so the guest\'s '
           'own address crosses the wan segment untranslated',
           [_masq_off('l2-03')])],
       timeout_s=600),

    _s('l2_04_dnat',
       'dnat rewrites the destination to the backend and restores the '
       'published address on the reply',
       [_p('dnat-to-wrong-backend',
           'the port forward points at a host that is not the backend',
           [PolicySub(tag='l2-04', find='dnat to 10.99.22.7:8080',
                      repl='dnat to 10.99.22.8:8080')])],
       witness_note='the subject is the REWRITE, which a socket cannot '
                    'report; the tap reads the addresses off the wire',
       timeout_s=240),

    _s('l2_05_pipeline_split',
       'a tail-call split pipeline behaves identically to the unsplit '
       'program it was cut from',
       [_p('split-diverges',
           'the split half enforces a different rule from the unsplit '
           'half — the exact failure an equivalence test exists to catch',
           [PolicySub(tag='l2-05b',
                      find='drop if pkt.proto == tcp and pkt.dst_port == 9999',
                      repl='drop if pkt.proto == tcp and pkt.dst_port == 9998')])],
       witness_note='equivalence of two runs; both halves measured the '
                    'same way, so the comparison carries the claim',
       timeout_s=300),

    _s('l2_06_storm_shield',
       'the shipped storm_shield example kills the broadcast-domain '
       'firehose and keeps the DHCP lease alive',
       [_p('dhcp-lease-eaten',
           'the DHCP-offer exemption names the wrong ports, so the shield '
           'also eats the reply that keeps the wan lease alive — a shield '
           'that takes its own address down with the noise',
           [PolicySub(tag='l2-06',
                      find='allow if pkt.proto == udp and pkt.src_port == 67 '
                           'and pkt.dst_port == 68',
                      repl='allow if pkt.proto == udp and pkt.src_port == 69 '
                           'and pkt.dst_port == 70')],
           residual='FOUND BY THIS SWEEP: the first plant here widened the '
                    'multicast drop to 225.0.0.0/8 and every "wire: X dead" '
                    'assertion stayed green, because the policy ends in a '
                    'catch-all `drop limited by rate_limit(2000, per=src_ip)` '
                    'and then `default drop`. Those assertions therefore '
                    'measure the policy\'s AGGREGATE effect and cannot '
                    'attribute a kill to the rule that names it: the three '
                    'noise rules could be deleted outright and the scenario '
                    'would still pass. Attribution needs the per-rule '
                    'counters to be asserted as the discriminator, or a '
                    'source sending under the flood-guard threshold.')],
       witness_note='disposition only',
       timeout_s=300),

    _s('l2_07_cross_zone_redirect',
       'a redirect across zones leaves the DUT on the second port and '
       'the switch sees it',
       [_p('redirect-becomes-allow',
           'the cross-zone redirect degrades to a plain allow: nothing '
           'leaves the wan port, and only the switch and NIC counters '
           'can say so',
           [PolicySub(tag='l2-07',
                      find='redirect to wan if pkt.src_ip == 10.99.33.5',
                      repl='allow if pkt.src_ip == 10.99.33.5')])],
       timeout_s=300),

    # ---------------- Layer 3: the daemon lifecycle ----------------
    _s('l3_01_hot_reload',
       'a policy reload lands under live traffic and the untouched flow '
       'loses nothing',
       [_p('watcher-never-fires',
           'the watcher is off, so no reload happens at all — the state '
           'in which zero loss is trivially true and means nothing',
           [FileSub(path='/etc/f/fd.yaml', find='  enabled: true',
                    repl='  enabled: false')],
           residual='an outage INSIDE the atomic swap cannot be planted '
                    'from the bench; it needs a mutated fd')],
       witness_note='the subject is LOSS, and a promiscuous tap can only '
                    'over-count relative to a real stack: it can hide a '
                    'delivery problem, never invent a delivered frame, so '
                    'sent-vs-arrived on one cable is the right shape here',
       timeout_s=300),

    _s('l3_02_ab_swap',
       'the changed rule flips mid-stream while the untouched flow is '
       'uninterrupted',
       [_p('pre-reload-rule-inert',
           'the pre-reload drop names the wrong source, so flow B was '
           'never blocked and the "flip" is not a flip',
           [PolicySub(tag='l3-02',
                      find='drop if pkt.proto == udp and pkt.src_ip == 10.99.53.2',
                      repl='drop if pkt.proto == udp and pkt.src_ip == 10.99.53.9')])],
       witness_note='as l3_01: the claim is that one flow lost nothing '
                    'and the other flipped, both measured as arrivals on '
                    'one cable; no delivery to a host is asserted',
       timeout_s=300),

    _s('l3_03_cold_boot',
       'the bundle auto-loads on a cold boot',
       declared='it reboots the rig and is driven from ksys; the sweep '
                'runs ON the rig and cannot survive its own subject. '
                'Planting the defect (a broken cold-boot path) would '
                'also need the box to come back to be measured.',
       witness_note='WEAK, and recorded as such: after the reboot the '
                    'only witnesses are the journal and fctl — the '
                    'daemon reporting on itself. A wire probe driven '
                    'from ksys once the box is back would make this a '
                    'real measurement; it does not have one today',
       timeout_s=60),

    _s('l3_05_crash_containment',
       'the XDP program keeps enforcing the last-committed policy with '
       'the daemon dead',
       [_p('datapath-dies-with-the-daemon',
           'an ExecStopPost detaches the program when the unit stops, so '
           'the datapath no longer outlives fd — exactly the property '
           'this scenario claims',
           [UnitDropIn(unit='fd',
                       body='[Service]\nExecStopPost=/bin/sh -c "ip link '
                            'set dev %s xdp off"\n' % RECV_IF)],
           verify='systemctl show fd -p ExecStopPost --value '
                  '| grep -q "xdp off"')],
       timeout_s=300),

    _s('l3_06_bad_commit',
       'a broken policy write does not disturb the policy that is '
       'running',
       [_p('running-policy-inert',
           'the running policy\'s drop names the wrong port, so "the old '
           'rule is still enforced" was never true to begin with',
           [PolicySub(tag='l3-06',
                      find='drop if pkt.proto == udp and pkt.dst_port == 6666',
                      repl='drop if pkt.proto == udp and pkt.dst_port == 6667')],
           residual='the other half — that a VALID replacement would '
                    'have been adopted — is not planted: the broken '
                    'policy is written straight to /etc/f/rules.fw and '
                    'never passes through the compile hook')],
       witness_note='disposition only: the claim is that the OLD rules '
                    'still bite, which the tap after XDP answers',
       timeout_s=300),

    _s('l3_07_boot_ordering',
       'the datapath is armed before network.target, by ordering rather '
       'than by luck: Type=notify plus a readiness notification after '
       'the attach',
       [_p('type-simple-again',
           'the unit goes back to Type=simple, which orders the exec() '
           'and not the attach — the state in which the measured '
           'ordering is a coincidence',
           [UnitDropIn(unit='fd', body='[Service]\nType=simple\n')],
           verify='[ "$(systemctl show fd -p Type --value)" = simple ]',
           residual='the journal timestamps come from the CURRENT boot, '
                    'so the two ordering assertions cannot be moved '
                    'without a reboot; this plant reaches the Type and '
                    'StatusText assertions that make them meaningful')],
       witness_note='WEAK, and recorded as such: the ordering is read '
                    'out of fd\'s own journal lines. The kernel-side '
                    'half — that no frame crossed before the attach — '
                    'has no witness on this bench, which is why the '
                    'Type=notify assertion carries the argument',
       timeout_s=180),

    _s('l3_08_confd_socket_survives_fd_restart',
       'restarting fd does not take f-confd\'s socket with it, so the '
       'anti-lockout rollback stays armed',
       [_p('runtimedirectory-not-preserved',
           'the original defect, put back verbatim: fd stops preserving '
           'the RuntimeDirectory it shares with f-confd, so `systemctl '
           'restart fd` unlinks /run/f and takes f-confd\'s live socket '
           'with it while f-confd stays `active` and unreachable',
           [UnitDropIn(unit='fd',
                       body='[Service]\nRuntimeDirectoryPreserve=no\n')],
           verify='[ "$(systemctl show fd -p RuntimeDirectoryPreserve '
                  '--value)" = no ]')],
       witness_note='the subject is a unix socket inode; systemd\'s own '
                    'is-active was true throughout the real defect, '
                    'which is why the check is on the socket',
       timeout_s=180),

    # ---------------- Layer 4: the switch as witness ---------------
    _s('l4_01_mirror_witness',
       'the switch delivered the frame and the DUT is where it died — '
       'ground truth the DUT cannot influence',
       [_p('drop-rule-misses',
           'the drop names an address nothing sends from, so the frame '
           'the mirror proves was delivered also survives the DUT',
           [PolicySub(tag='l4-01', find='drop if pkt.src_ip == 10.99.71.2',
                      repl='drop if pkt.src_ip == 10.99.71.3')])],
       timeout_s=300),

    # ---------------- Layer 5: boundaries --------------------------
    _s('l5_01_boundaries',
       'inclusive ranges, port 0 and 65535, /32 and /0, icmp type 0 and '
       '255 — the places off-by-one lives',
       [_p('range-loses-its-upper-end',
           'the inclusive range 5000..5002 becomes 5000..5001, the '
           'classic exclusive-upper-bound defect',
           [PolicySub(tag='l5-01', find='pkt.dst_port in 5000..5002',
                      repl='pkt.dst_port in 5000..5001')])],
       witness_note='the subject is which frames MATCH, so counters are '
                    'the right witness',
       timeout_s=240),

    _s('l5_02_precedence',
       '`and` binds tighter than `or`, as the spec says and not as the '
       'reader assumes',
       [_p('or-binds-tighter',
           'the unparenthesised form is compiled as if `or` bound '
           'tighter — precisely the reading the spec warns against',
           [PolicySub(tag='l5-02a',
                      find='pkt.proto == tcp or pkt.proto == udp '
                           'and pkt.dst_port == 443',
                      repl='(pkt.proto == tcp or pkt.proto == udp) '
                           'and pkt.dst_port == 443')])],
       witness_note='disposition only',
       timeout_s=300),

    _s('l5_03_rate_limit_boundary',
       'exactly N packets per bucket per second are NOT dropped; N+1 is, '
       'and buckets are independent per source',
       [_p('threshold-off-by-most',
           'the threshold collapses to 1, so the boundary case — exactly '
           'N, nothing dropped — stops holding',
           [PolicySub(tag='l5-03', regex=True,
                      find=r'rate_limit\((?:\d+|\$\w+), per=src_ip\)',
                      repl='rate_limit(1, per=src_ip)')])],
       witness_note='disposition only',
       timeout_s=300),

    # ---------------- Layer 6: ugly frames -------------------------
    _s('l6_01_fragments',
       'a non-first fragment carries no L4 header and must not match L4 '
       'rules, while still being counted at IP level',
       [_p('l4-rule-inert',
           'the port rule names a port nothing sends to, so the baseline '
           'the fragment cases are compared against is not there',
           [PolicySub(tag='l6-01',
                      find='allow if pkt.proto == tcp and pkt.dst_port == 443',
                      repl='allow if pkt.proto == tcp and pkt.dst_port == 444')],
           residual='the fragment property ITSELF — reading L4 at ihl*4 '
                    'without checking the fragment offset — is a '
                    'datapath property and needs a mutated emitter; this '
                    'plant reaches only its baseline')],
       witness_note='disposition only',
       timeout_s=300),

    _s('l6_02_malformed',
       'IP options, XMAS/NULL flags, bad checksums and QinQ do not crash '
       'the program and get their documented disposition',
       [_p('port-rule-inert',
           'the port rule names 444, so the frames that prove the L4 '
           'offset is computed from ihl*4 are dropped instead of passed',
           [PolicySub(tag='l6-02',
                      find='allow if pkt.proto == tcp and pkt.dst_port == 443',
                      repl='allow if pkt.proto == tcp and pkt.dst_port == 444')],
           residual='"nothing crashed the program" cannot be broken by a '
                    'policy edit; a real verifier or JIT fault needs a '
                    'mutated emitter')],
       witness_note='disposition only',
       timeout_s=300),

    # ---------------- Layer 7: tier 2 ------------------------------
    _s('l7_01_tier2_rate_limit_gap',
       'the Tier 1 rate_limit MODIFIER caps a flood, and the Tier 2 CALL '
       'form does not fire at all (a recorded gap)',
       [_p('tier1-budget-infinite',
           'the Tier 1 modifier\'s budget goes to a million, so the '
           'control half of the comparison stops capping',
           [PolicySub(tag='l7-01a', regex=True,
                      find=r'rate_limit\((?:\d+|\$\w+), per=src_ip\)',
                      repl='rate_limit(1000000, per=src_ip)')],
           residual='the Tier 2 half asserts a gap in the compiler; '
                    'closing or breaking it needs an emitter change')],
       witness_note='disposition only',
       timeout_s=300),

    _s('l7_02_tier2_semantics',
       'the Tier 2 if/elif/else chain, its implicit fall-through PASS, '
       'terminal actions stopping evaluation, and refactor invariance',
       [_p('if-branch-verdict-flipped',
           'the first branch allows what it should drop',
           [PolicySub(tag='l7-02a', regex=True,
                      find=r'( +)count ssh\n( +)drop',
                      repl=r'\1count ssh\n\2allow')])],
       witness_note='disposition only',
       timeout_s=360),

    _s('l7_03_multidef_zones',
       'a terminal action inside a helper returns from the caller, and '
       'a helper\'s side effects land in ONE shared counter slot',
       [_p('helper-terminal-not-terminal',
           'the helper\'s drop becomes an allow, so a terminal action '
           'inside a helper stops being terminal for the caller',
           [PolicySub(tag='l7-03a', regex=True,
                      find=r'( +)count helper_hits\n( +)drop',
                      repl=r'\1count helper_hits\n\2allow')])],
       witness_note='disposition only',
       timeout_s=300),

    # ---------------- Layer 8: bundles, pins, config ---------------
    _s('l8_01_objectless_bundle',
       'a bundle with no compiled objects must not silently detach the '
       'whole firewall, on either the cold-boot or the reload path',
       [_p('running-policy-inert',
           'the running policy\'s drop names the wrong port, so "the '
           'policy was enforcing before the bad adopt" was never true',
           [PolicySub(tag='l8-01*',
                      find='drop if pkt.proto == udp and pkt.dst_port == 6000',
                      repl='drop if pkt.proto == udp and pkt.dst_port == 6001')],
           residual='the refusal itself lives in fd\'s load path; this '
                    'plant reaches the two enforcement preconditions '
                    'that make the refusal readable')],
       timeout_s=420),

    _s('l8_02_conntrack_gc',
       'conntrack tracks flows and its garbage collector is alive in '
       'bundle mode',
       [_p('nothing-is-tracked',
           'the explicit allow on a NEW flow no longer matches, so no '
           'conntrack entry is created and there is nothing to collect',
           [PolicySub(tag='l8-02',
                      find='allow if pkt.proto == tcp and pkt.tcp.syn',
                      repl='allow if pkt.proto == tcp and pkt.tcp.fin')],
           residual='the `enabled` flag branch — GC dead in bundle mode '
                    '— is set inside fd and needs a mutated daemon')],
       witness_note='the subject is a kernel map\'s occupancy over time; '
                    'no wire witness can report it',
       timeout_s=420),

    _s('l8_03_attach_truth',
       'the kernel, not fctl status, is the ground truth for whether a '
       'program is attached',
       [_p('policy-not-enforcing',
           'the drop names the wrong port, so the "before" state this '
           'scenario compares the detach against is not enforcement',
           [PolicySub(tag='l8-03',
                      find='drop if pkt.proto == udp and pkt.dst_port == 6100',
                      repl='drop if pkt.proto == udp and pkt.dst_port == 6101')])],
       timeout_s=300),

    _s('l8_04_watcher_mtime',
       'the watcher detects an ordinary edit (the positive control) and '
       'misses an mtime-preserving replacement (the recorded gap)',
       [_p('watcher-off',
           'the watcher is disabled, so the positive control — an '
           'ordinary edit IS detected — stops holding, and the negative '
           'case it licenses proves nothing',
           [FileSub(path='/etc/f/fd.yaml', find='  enabled: true',
                    repl='  enabled: false')])],
       witness_note='the wire half is disposition only (which port the '
                    'live policy blocks); the reload count comes from '
                    'the journal, and the two disagreeing is the whole '
                    'finding',
       timeout_s=360),

    _s('l8_05_stale_ifaces',
       'an interface a reload ADDED to a zone is attached, and a clean '
       'stop detaches it',
       [_p('watcher-off',
           'the watcher is disabled, so the reload never happens and the '
           'interface is never added — the scenario\'s subject never '
           'comes into existence',
           [FileSub(path='/etc/f/fd.yaml', find='  enabled: true',
                    repl='  enabled: false')])],
       witness_note='the subject is which netdevs carry a program; '
                    '`ip -d link show` is the kernel\'s own answer',
       timeout_s=300),

    _s('l8_06_config_and_signals',
       'a broken config is loud, a clean stop detaches XDP, and the box '
       'is attached and running after a SIGHUP',
       [_p('stop-does-not-detach',
           'the unit is killed with SIGKILL instead of SIGTERM, so fd '
           'never runs its clean shutdown and the program is left '
           'attached with no daemon',
           [UnitDropIn(unit='fd', body='[Service]\nKillSignal=SIGKILL\n')],
           verify='[ "$(systemctl show fd -p KillSignal --value)" '
                  '= SIGKILL ]')],
       witness_note='the subject is unit behaviour and netdev state',
       timeout_s=360),

    _s('l8_07_bundle_map_isolation',
       'zone-private pinned maps are one kernel map PER ZONE; only '
       'bundle-global state is shared',
       [_p('zone-a-counter-inert',
           'zone a\'s counter names traffic that does not arrive, so the '
           'isolation comparison has nothing on one side of it',
           [PolicySub(tag='l8-07c', find='count a_hits',
                      repl='count a_hits if pkt.src_ip == 10.99.253.253')],
           residual='the SHARING invariant itself is enforced at compile '
                    'time and by libbpf; breaking it needs an emitter '
                    'change, and the compiler now refuses the shapes '
                    'that used to produce it')],
       witness_note='the subject is kernel map identity; bpftool is the '
                    'only witness that can answer it',
       timeout_s=420),

    _s('l8_08_rate_limit_scope',
       'rate_limit scope=global spends ONE budget across two '
       'independently-compiled zone objects; scope=zone does not',
       [_p('global-is-really-zone',
           'the bundle compiled with scope=global gets zone-scoped '
           'buckets, so each zone spends its own budget while the policy '
           'says one',
           [PolicySub(tag='l8-08-global', find='scope=global',
                      repl='scope=zone')])],
       witness_note='disposition across two zones; the counters and the '
                    'tap both report it',
       timeout_s=420),

    _s('l8_09_stale_pins_cold_boot',
       'a cold boot over a DIRTY pin root reconciles it: policy-scoped '
       'pins are discarded, flow-keyed ones adopted',
       [_p('pin-root-cleared-first',
           'the historical hw::deploy workaround, put back: the pin root '
           'is wiped before the restart, so fd cold-boots onto a clean '
           'bpffs the field never has and reconciles nothing',
           [DeployCmd(tag='l8-09b', phase='pre',
                      cmd='rm -f %s/fwl_* 2>/dev/null || true' % PIN)])],
       witness_note='the subject is kernel map identity and lifetime',
       timeout_s=420),

    _s('l8_10_reload_preserves_conntrack',
       'a policy reload keeps the flow-keyed pins: an established flow '
       'is still established to the new program',
       [_p('watcher-off',
           'the watcher is disabled, so the reload this scenario measures '
           'across never happens',
           [FileSub(path='/etc/f/fd.yaml', find='  enabled: true',
                    repl='  enabled: false')],
           residual='discarding conntrack ACROSS a real reload is a '
                    'daemon behaviour; planting it needs a mutated fd')],
       witness_note='kernel map identity plus the datapath\'s own reading '
                    'of the adopted table',
       timeout_s=420),

    _s('l8_11_log_zone_attribution',
       'a logged event names the zone that emitted it, so two zones '
       'writing into one ring stay distinguishable',
       [_p('one-zone-logs-nothing',
           'zone zb\'s log rule names a port nothing sends to, so only '
           'one zone writes into the ring and the cross-attribution '
           'assertions have nothing to be wrong about',
           [PolicySub(tag='l8-11',
                      find='log if pkt.proto == udp and pkt.dst_port == 7802',
                      repl='log if pkt.proto == udp and pkt.dst_port == 7899')])],
       witness_note='the ring buffer is the subject',
       timeout_s=360),

    # ---------------- Layer 9: load and link events ----------------
    _s('l9_01_percpu_counters',
       'a per-CPU counter sums exactly across every CPU when RSS spreads '
       'traffic over queues',
       [_p('counter-misses-a-source-block',
           'the counter\'s CIDR is narrowed to a /25, so half the source '
           'addresses stop being counted — indistinguishable from a '
           'missed CPU unless the assertion is exact',
           [PolicySub(tag='l9-01', find='pkt.src_ip in 10.99.180.0/24',
                      repl='pkt.src_ip in 10.99.180.0/25')])],
       witness_note='the counter IS the subject',
       timeout_s=300),

    _s('l9_02_link_events',
       'a link flap and a switch-side bounce leave the same program '
       'attached and still enforcing, with no operator action',
       [_p('policy-not-enforcing',
           'the drop names the wrong port, so "still enforcing" after the '
           'flap was never enforcement before it',
           [PolicySub(tag='l9-02',
                      find='drop if pkt.proto == udp and pkt.dst_port == 6300',
                      repl='drop if pkt.proto == udp and pkt.dst_port == 6301')])],
       timeout_s=360),

    _s('l9_03_throughput',
       'every frame the NIC accepted is counted exactly once at line-ish '
       'rate, split and unsplit alike',
       [_p('split-counts-different-traffic',
           'the split variant\'s counter names a different source, so the '
           'two halves stop counting the same traffic',
           [PolicySub(tag='l9-03b', find='count total if pkt.src_ip == 10.99.192.1',
                      repl='count total if pkt.src_ip == 10.99.192.9')])],
       witness_note='the counter IS the subject; the AF_PACKET tap '
                    'legitimately drops frames at this rate',
       timeout_s=420),

    # ---------------- Layer 10/11: ceilings and NAT ----------------
    _s('l10_01_conntrack_capacity',
       'the conntrack table fills under a flow flood, reports itself '
       'while it does, and recovers when the flows go idle',
       [_p('new-flows-not-admitted',
           'the explicit SYN allow names FIN, so no new flow is admitted '
           'and nothing fills the table',
           [PolicySub(tag='l10-01',
                      find='allow if pkt.proto == tcp and pkt.tcp.syn',
                      repl='allow if pkt.proto == tcp and pkt.tcp.fin')])],
       witness_note='table occupancy over time; no wire witness applies',
       timeout_s=900),

    _s('l10_02_ratelimit_evasion',
       'a rate limit keyed per source is evaded by source diversity once '
       'the 4096-bucket table is full — a recorded property, with a '
       'single-source control that must be capped',
       [_p('control-budget-infinite',
           'the control\'s budget goes to a million, so the one '
           'assertion in this scenario that can fail stops holding',
           [PolicySub(tag='l10-02', regex=True,
                      find=r'rate_limit\((?:\d+|\$\w+), per=src_ip\)',
                      repl='rate_limit(1000000, per=src_ip)')],
           residual='the evasion half is reported through two '
                    'conditionals whose branches both call pass(); no '
                    'plant can move them, which the static lint reports '
                    'separately')],
       witness_note='disposition only',
       timeout_s=600),

    _s('l11_01_masq_port_collision',
       'two hosts that pick the same ephemeral port to the same '
       'destination get distinct mappings, and each reply reaches its '
       'own host',
       [_p('masquerade-does-not-match',
           'the masquerade rule stops matching the test hosts, so no '
           'mapping is claimed and no collision can be detected',
           [_masq_off('l11-01')])],
       witness_note='the subject is which host a translated reply is '
                    'addressed to, read off the wire; the far sides here '
                    'are frame builders, not stacks',
       timeout_s=600),

    _s('l11_02_nat_table_ceiling',
       'fwl_nat refuses at its cap rather than misdelivering, counts the '
       'refusals, and reclaims mappings when their flows end',
       [_p('masquerade-does-not-match',
           'the masquerade rule stops matching the flood, so the table '
           'never fills and neither the cap nor the reclamation is '
           'exercised',
           [_masq_off('l11-02')])],
       witness_note='table occupancy and refusal counters over 80 000 '
                    'flows; no socket can witness that',
       timeout_s=1500),

    _s('l11_03_gc_under_churn',
       'conntrack GC keeps up under churn and the datapath is untouched '
       'while it runs',
       [_p('control-flow-dropped',
           'the control flow — the one that must keep crossing while the '
           'table churns — is no longer admitted',
           [PolicySub(tag='l11-03',
                      find='allow if pkt.src_ip == 10.99.51.1 and pkt.proto == tcp',
                      repl='allow if pkt.src_ip == 10.99.51.9 and pkt.proto == tcp')])],
       witness_note='latency and occupancy under churn',
       timeout_s=900),

    _s('l11_04_masq_established_reply',
       'masquerade composes with `in [established, related]`: the reply '
       'to a masqueraded flow is de-NATed and delivered, proven by a '
       'real far-side socket',
       [_p('masquerade-does-not-match',
           'the office policy stops masquerading, so the composition '
           'this scenario exists to prove is not exercised',
           [_masq_off('l11-04c')])],
       timeout_s=900),

    _s('l11_05_icmp_pmtu',
       'an RFC 1191 frag-needed naming a translated flow is classified '
       '`related`, RFC 5508-translated, and delivered to the host that '
       'owns the flow',
       [_p('related-not-admitted',
           'the policy is written `== established`, the spelling every '
           'policy shipped before this used: an ICMP error carries no '
           'ports, reads NEW, and dies at `default drop`',
           [PolicySub(tag='l11-05',
                      find='allow if conntrack(pkt).state in [established, related]',
                      repl='allow if conntrack(pkt).state == established')])],
       witness_note='an embedded datagram header and three checksums; no '
                    'socket can report any of it',
       timeout_s=1500),

    _s('l11_06_nat_occupancy_curve',
       'the occupancy curve is FLAT under a steady workload — mappings '
       'are freed as fast as flows arrive',
       [_p('masquerade-does-not-match',
           'nothing is translated, so the curve is flat at zero and a '
           'flat curve stops meaning mappings are being freed',
           [_masq_off('l11-06')])],
       witness_note='occupancy over time',
       timeout_s=900),

    # ---------------- Layer 12: the box\'s own traffic --------------
    _s('l12_01_box_originated_flows',
       'finding A4 reproduces: a flow the box itself originates gets no '
       'conntrack entry, so `default drop` eats its replies — and a TC '
       'egress hook sees exactly the gap and not the forwarded traffic',
       [_p('wan-zone-admits-everything',
           'the wan zone defaults to allow, so the replies survive and '
           'the finding stops reproducing — the shape this scenario '
           'would take if the gap were closed by accident',
           [PolicySub(tag='l12-01', find='default drop',
                      repl='default allow')])],
       timeout_s=600),
]}
