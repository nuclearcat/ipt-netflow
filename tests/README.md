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
resizers. It also checks no-op writes, a two-table allocation peak, cached tuple
hashes, and that resizing performs no tuple hashing. These substitutes validate
the locking and lifetime contracts; they do not emulate the kernel's RCU
implementation or interrupt context.

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

## Production benchmark: 2026-10-25

The follow-up fixes in `7c37663` eliminate unnecessary hashsize rehashes and
shorten resize operations. Steady-state NETFLOW packet cost is effectively
unchanged compared with `c6011d8`, which already contains striped tables and
RCU aggregation. These measurements compare the follow-ups, rather than the
original global-reader-lock implementation.

The test host was `th-pppoe25`, with 48 online CPUs (Intel Xeon Gold 5118),
kernel `7.2.11-build-0140`, NetFlow v5, hashsize 655360, and aggregation disabled.
The production flow structure remained 160 bytes. The candidate was built
using the running kernel's extracted configuration and GCC 15.2, and reported
version `2.8.0-41-g7c37663`.

### Steady-state perf comparison

Each version had three 20-second system-wide `cycles` captures at 49 Hz with
frame-pointer callchains. `perf stat` ran concurrently with each recording:

```sh
perf record -a -e cycles -F 49 -g -o system.data -- sleep 20 &
recorder=$!
perf stat -a -e cycles,instructions,context-switches,cpu-migrations,page-faults \
    -o perf-stat.txt -- sleep 20
wait "$recorder"
```

Module-specific symbol roots and contemporaneous `/proc/kallsyms` snapshots
resolved each capture against the correct module. Counter snapshots included
`/proc/uptime`, `/proc/stat`, `/proc/net/dev`, `/proc/net/softnet_stat`, and
`/proc/net/stat/ipt_netflow`. The candidate warmed up for several minutes before
profiling. Targeted sysctl timings ran separately from the accepted perf windows.

| Measurement | c6011d8 | 7c37663 |
| --- | ---: | ---: |
| Accepted cycle samples | 141,244 | 141,233 |
| Lost samples | 0 | 0 |
| NETFLOW inclusive cycle share | 2.726% | 2.652% |
| Per-window NETFLOW share range | 2.644–2.803% | 2.613–2.678% |
| Estimated NETFLOW cycles/accounted packet | 519.26 | 516.53 |
| Accounted packet rate | 960,271/s | 938,240/s |
| System-wide cycles/accounted packet | 19,089 | 19,521 |
| Reader-lock/unlock share beneath NETFLOW | 0% sampled | 0% sampled |
| Reported module packet drops | 0 | 0 |

Packet rate is the change in the module's total accounted-packet counter divided
by the uptime difference between snapshots. Estimated NETFLOW cycles per packet
divide the sum of sampled periods for callchains containing `netflow_target` by
packet rate times the perf measurement duration. Aggregates sum the cycle and
packet exposures across the three windows. The counter intervals were about
21.2 seconds, so normalization assumes their average traffic rate represents
the 20-second perf interval.

The estimated NETFLOW change was -0.53%, within the observed window variation.
System-wide cycles per packet increased 2.26% while packet rate decreased 2.29%.
System-wide counters include unrelated activity and idle paths. Changing live
traffic and flow mix prevent an overall CPU-saving or throughput claim.

The accepted baseline windows started at 13:24:35, 13:24:56, and 13:26:15 UTC;
candidate windows started at 13:30:04, 13:30:25, and 13:30:46 UTC. One earlier
baseline window overlapped the sysctl timing tests and was excluded and replaced.

### Hashsize operation timings

The [timing helper](benchmarks/hashsize_bench.c) opens the sysctl afresh for each
write and reports wall time (`CLOCK_MONOTONIC`) and process CPU time
(`CLOCK_PROCESS_CPUTIME_ID`). The table shows medians of three iterations:

| Operation | Before wall/CPU time | After wall/CPU time |
| --- | ---: | ---: |
| Zero-length write | 50.484 / 50.479 ms | 2.147 / 1.875 us |
| Write the current size | 55.865 / 55.797 ms | 2.073 / 1.821 us |
| Resize 655360 -> 655616 -> 655360 | 99.107 / 99.097 ms | 87.026 / 87.018 ms |

Empty and same-size writes now avoid allocating or rehashing the table. The
resize-and-restore pair was 12.2% faster in this observation. Mean endpoint flow
counts were 247,348 before and 239,033 after, about 3.4% lower afterward, so the
entire resize difference cannot be attributed to cached hashes.

Build and run the helper independently of steady-state perf collection:

```sh
gcc -O2 -static -Wall -Wextra tests/benchmarks/hashsize_bench.c \
    -o /tmp/hashsize-bench
sudo /tmp/hashsize-bench empty
sudo /tmp/hashsize-bench noop
sudo /tmp/hashsize-bench resize
```

This helper writes live sysctls. Resize mode increases the size by 256 and
restores it on normal completion or ordinary error exit; forced termination can
interrupt restoration. The recorded run finished at the original size 655360.

### Validation and deployment

Packet, aggregation, hash-table, exporter, and NAT registration checks passed
under ASan/UBSan, including the legacy RCU-sched and hash-sampling variants.
The exact production candidate passed QEMU tests with the production kernel:
NetFlow v9/IPFIX accounting through conntrack events and iptables, packet/byte
totals after hashsize operations, flow dumps, and repeated module unloading.

Runtime replacement preserved parameters and firewall rule order, with an
approximately 0.24-second accounting pause. Exports resumed without reported
packet drops or export loss; kernel taint was unchanged and no new kernel
warnings appeared. The boot image was unchanged.

[Machine-readable results](benchmarks/2026-10-25-reader-locks.json) preserve the
per-window cycle sums, packet counters, timestamps, all timing samples,
normalization details, and candidate module identity. Raw perf captures and
symbol snapshots remain outside the repository.
