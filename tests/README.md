# Focused regression checks

Run from the repository root with Python 3 and GCC with AddressSanitizer and
UndefinedBehaviorSanitizer support:

```sh
python3 tests/test_packets.py
python3 tests/test_aggregation.py
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

`--baseline` on the packet and SNMP checks exercises the reviewed `f6133dd`
revision and reports its expected failures instead of exiting unsuccessfully.
The synthetic kernel-service substitutes do not establish network reachability
or replace live-kernel fault-injection, unloading, or concurrency testing.
