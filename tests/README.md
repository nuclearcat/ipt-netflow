# Focused regression checks

Run from the repository root with Python 3 and GCC with AddressSanitizer and
UndefinedBehaviorSanitizer support:

```sh
python3 tests/test_packets.py
python3 tests/test_aggregation.py
python3 tests/test_hashtable.py
python3 tests/test_exports.py
python3 tests/test_registration.py
python3 tests/test_snmp.py
python3 tests/test_snmp.py --row
```

The SNMP checks additionally require the Net-SNMP development headers and agent
libraries. `NET_SNMP_INCLUDE` and `NET_SNMP_LIBS` override their include directory
and linker flags when they are installed outside the default search paths.

These checks compile production parser/exporter functions extracted from the
current sources, with small substitutes for kernel services. The SNMP checks
compile the complete plugin against Net-SNMP and substitute only its proc-file
input. Temporary sources and binaries are removed automatically.

Coverage includes copied IP headers, truncated and valid IPv6 AH headers, all
Traffic Class values, Flow Label isolation, first/atomic/later IPv6 fragments,
aggregation rollback after invalid input or allocation failure, PDU padding near
the buffer limit, v5 timestamps, large hash counters, option bitmaps, SPI shifts,
NAT module references and concurrent registration transitions, large SNMP
snapshots, long/unterminated lines, and rejection of unsupported table types.

The aggregation check also runs the packet aggregation code during concurrent
ruleset replacement and holds an old reader across publication to check delayed
reclamation. It checks teardown with both modern and legacy RCU-sched branches,
including a retained ordinary RCU reader and the number of grace-period waits.
The hash-table check exercises the production lookup, resize and
export-scan code with pthread locks, both with and without hash sampling. It
checks non-power-of-two sizes, allocation failure, export-list ordering, bucket
links, and packet/byte conservation during concurrent updates, exports and two
resizers. These substitutes validate the locking and lifetime contracts; they
do not emulate the kernel's RCU implementation or interrupt context.

For live validation of the reader-lock change, use a test kernel with lockdep,
RCU debugging and KASAN, drive traffic on several CPUs, and alternate hash sizes
(including 256, 257 and 65537) while reading the flow dump and replacing
aggregation rules. Include forced exports and unload/reload after stopping
traffic. Compare `perf record -a -g` samples and cycles per packet before and
after using the same workload, CPU affinity and export settings. The packet
path should have no hash-table or aggregation reader-lock calls; stripe
spinlocks and matched-rule atomic usage counters remain. Removing the reported
3.1% reader-lock cost is a profiling target, not a measured speedup.

`--baseline` on the packet and SNMP checks exercises the reviewed `f6133dd`
revision and reports its expected failures instead of exiting unsuccessfully.
The synthetic kernel-service substitutes do not establish network reachability
or replace live-kernel fault-injection, unloading, or concurrency testing.
