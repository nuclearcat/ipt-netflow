# ipt_NETFLOW

[![Kernel CI](https://github.com/nuclearcat/ipt-netflow/actions/workflows/testing-kernels.yaml/badge.svg?branch=master)](https://github.com/nuclearcat/ipt-netflow/actions/workflows/testing-kernels.yaml)
[![Latest tested kernel](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fnuclearcat%2Fipt-netflow%2Fmaster%2F.github%2Fkernel-matrix.json&query=%24.latest&label=latest%20kernel&logo=linux&logoColor=black&color=FCC624)](https://github.com/nuclearcat/ipt-netflow/actions/workflows/testing-kernels.yaml)
[![Tested LTS kernels](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fnuclearcat%2Fipt-netflow%2Fmaster%2F.github%2Fkernel-matrix.json&query=%24.lts&label=LTS%20kernels&color=2ea44f)](https://github.com/nuclearcat/ipt-netflow/actions/workflows/testing-kernels.yaml)

High-performance NetFlow v5, v9, and IPFIX flow-data export module for Linux.
It supports iptables NETFLOW targets and direct netfilter-hook capture for
nftables-only systems.

Originally developed by <abc@openwall.com> (2008-2025). Continued development
by <denys.f@collabora.com> since 2025.

## Detailed Feature List

   * High performance and scalability. For highest performance module could be
     run without conntrack being enabled in kernel. Reported to be able to
     handle 10Gbit traffic with more than 1500000 pps with negligible server
     load (on S5500BC).

   * NetFlow v5, v9, and IPFIX are fully supported.

     Support of v9/IPFIX is adding flexibility to exporting of flow data
     plus greater visibility of traffic, letting export many additional fields
     besides what was possible in v5 era. Such as
     
   * IPv6 option headers, IPv4 options, TCP options, ethernet type, dot1q
     service and customer VLAN ids, MAC addresses, and

   * Full IPv6 support,

   * NAT translations events (from conntrack) using NetFlow Event Logging (NEL).
     This is standardized way for v9/IPFIXr, but module export such events even
     for v5 collectors via specially crafted pseudo-records.

   * Deterministic (systematic count-based), random and hash Flow Sampling.
     With appropriate differences in support of v5, v9, and IPFIX.

   * SNMP agent (for net-snmp) for remote management and monitoring.

   * Options Templates (v9/IPFIX) let export useful statistical,
     configurational, and informational records to collector.
     Such as metering, exporting, sampling stat and reliability stat, sampling 
     configuration, network devices ifName, ifDescr list.

   * Automated CI tests current stable and LTS Linux releases, with the exact
     kernel versions shown in the badges above.

   * Module load time and run-time (via sysctl) configuration.

   * Flexibility in enabling features via ./configure script. This will let you
     disable features you don't need, which increase compatibility with custom
     kernels and performance.

   * SNMP-index translation rules, let convert meaningless and unstable
     interface indexes (ifIndex) to more meaningful numbering scheme.

   * Easy support for catching mirrored traffic with promisc option. Which is
     also supporting optional MPLS decapsulation and MPLS-aware NetFlow.


## Obtaining the Latest Version

```sh
git clone https://github.com/nuclearcat/ipt-netflow.git
cd ipt-netflow
```


## Installation

   Five easy steps.

### 1. Prepare Kernel source

   If you have package system install kernel-devel package, otherwise install
   raw kernel source from http://kernel.org matching _exactly_ version of your
   installed kernel.

   a) What to do for Centos:

      ~# yum install kernel-devel

   b) What to do for Debian and Ubuntu:

      ~# apt-get install module-assistant
      ~# m-a prepare

   c) Otherwise, if you downloaded raw kernel sources don't forget to create
    .config by copying it from your distribution's kernel. Its copy could reside
    in /boot or sometimes in /proc, examples:

      kernel-src-dir/# cp /boot/config-`uname -r` .config
    or
      kernel-src-dir/# zcat /proc/config.gz > .config

    Assuming you unpacked kernel source into the `kernel-src-dir/` directory.
    Then run:

      kernel-src-dir/# make oldconfig

    After that you'll need to prepare kernel for modules build:

      kernel-src-dir/# make prepare modules_prepare

   Note: Don't try to `make prepare` in Centos kernel-devel package directory
     (which is usually something like /usr/src/kernels/2.6.32-431.el6.x86_64)
     as this is wrong and meaningless.

### 2. Prepare Iptables

   Before this step it also would be useful to install pkg-config if don't
   already have.

   If you have package system just install iptables-devel (or on Debian, Ubuntu
   and derivatives libxtables-dev if available, otherwise iptables-dev)
   package, otherwise install iptables source matching version of your
   installation from ftp://ftp.netfilter.org/pub/iptables/

   a) What to do for Centos:

      # yum install iptables-devel

   b) What to do for Debian or Ubuntu:

      # apt-get install iptables-dev pkg-config

   c) Otherwise, for raw iptables source build it and make install.

### 3. Prepare net-snmp (optional)

  In case you want to manage or monitor module performance via SNMP you
  may install net-snmp. If you want to skip this step run configure
  with --disable-snmp-agent option.

  a) For Centos:

      # yum install net-snmp net-snmp-devel

  b) For Debian or Ubuntu:

      # apt-get install snmpd libsnmp-dev

  c) Otherwise install net-snmp from www.net-snmp.org

### 4. Build the module

```sh
./configure
make all install
depmod
```

This installs the kernel module and iptables-specific library.

Troubleshooting:

- Some older systems require an explicit compiler, for example
  `make CC=gcc-3.3`.
- Build against kernel sources that match the kernel you will run. If you use a
  `kernel-devel` package, confirm that its version matches your kernel package.
- If sources are in non-standard locations, run `./configure --help` for the
  available path options.
- To run `irqtop` on Debian 8, install its dependencies:

  ```sh
  apt-get install ruby ruby-dev ncurses-dev
  gem install curses
  ```

- If the build still fails, [open an issue](https://github.com/nuclearcat/ipt-netflow/issues).

### 5. Load the module

After this point you should be able to load the module and use the NETFLOW
target in iptables. See the next section.


## Configure Options

The configure script supports these optional features:

- `--enable-natevents` — Enable NetFlow Event Logging (NEL). This requires
  conntrack support and the `nf_conntrack` module, which is normally loaded
  automatically after `depmod`. If you do not run `make install`, load it
  manually.
- `--enable-sampler` — Enable flow sampling.
- `--enable-sampler=hash` — Also enable hash-based flow sampling.
- `--disable-snmp-agent` — Disable the net-snmp agent, which is built by
  default.
- `--enable-snmp-rules` — Enable SNMP-index conversion rules.
- `--enable-macaddress` — Export source and destination MAC addresses for
  NetFlow v9/IPFIX and include them in the flow key.
- `--enable-vlan` — Export outer and customer dot1q VLAN IDs and priorities.
  Enabling this or `--enable-macaddress` also exports the Ethernet packet type
  as `ethernetType(256)`.
- `--enable-direction` — Export `flowDirection(61)` for NetFlow v9/IPFIX.
  PREROUTING and INPUT are ingress, OUTPUT and POSTROUTING are egress, and
  FORWARD is undefined (`255`).
- `--enable-aggregation` — Enable aggregation rules.
- `--disable-dkms` — Do not create `dkms.conf` or install into the DKMS tree.
- `--disable-dkms-install` — Create `dkms.conf`, but skip automatic DKMS
  installation.
- `--enable-physdev` — Export `ingressPhysicalInterface(252)` and
  `egressPhysicalInterface(253)` for bridges. Use
  `--enable-physdev-override` if physical interfaces should replace the normal
  ingress and egress interface fields.
- `--enable-promisc` — Capture promiscuous packets in raw/PREROUTING. See
  [README.promisc](README.promisc) for usage details.
- `--promisc-mpls[=n]` — Enable MPLS decapsulation and MPLS-aware NetFlow for
  IPv4 and IPv6. The default exported label depth is 3, the maximum is 10, and
  0 disables label reporting.


## Running

1. You can load module directly by insmod like this:

   ```sh
   insmod ipt_NETFLOW.ko destination=127.0.0.1:2055 debug=1
   ```

   Or if properly installed (make install; depmod) by this:

   ```sh
   modprobe ipt_NETFLOW destination=127.0.0.1:2055
   ```

   See, you may add options in insmod/modprobe command line, or add
   them in /etc/modprobe.conf or /etc/modprobe.d/ipt_NETFLOW.conf
   like thus:

   ```text
   options ipt_NETFLOW destination=127.0.0.1:2055 protocol=9 natevents=1
   ```

2. Statistics is in /proc/net/stat/ipt_netflow
   Machine readable statistics is in /proc/net/stat/ipt_netflow_snmp
   To view boring slab statistics: grep ipt_netflow /proc/slabinfo
   Dump of all flows is in /proc/net/stat/ipt_netflow_flows

3. You can view parameters and control them via sysctl, example:

   ```sh
   sysctl net.netflow
   sysctl net.netflow.hashsize=32768
   ```

   Note: For after-reboot configuration I recommend to store module parameters
   in modprobe configs instead of storing them in /etc/sysctl.conf, as it's
   less clear when init process will apply sysctl.conf, before of after
   module's load.

4. Example of directing all IPv4 traffic into the module:

   ```sh
   iptables -I FORWARD -j NETFLOW
   iptables -I INPUT -j NETFLOW
   iptables -I OUTPUT -j NETFLOW
   ```

   Note: It is preferable (because easier to understand) to _insert_
   NETFLOW target at the top of the chain, otherwise not all traffic may
   reach NETFLOW if your iptables configuration is complicated and some
   other rule inadvertently consume the traffic (dropping or acepting before
   NETFLOW is reached). It's always good to test your configuration.
   Use  iptables -L -nvx  to check pkts/bytes counters on the rules.

5. If you want to account IPv6 traffic you should use protocol 9 or 10.
   Example of directing all IPv6 traffic into the module:

   ```sh
   sysctl net.netflow.protocol=10
   ip6tables -I FORWARD -j NETFLOW
   ip6tables -I INPUT -j NETFLOW
   ip6tables -I OUTPUT -j NETFLOW
   ```

   Note: First enable right version of protocol and after that add ip6tables
     rules, otherwise you will get errors in dmesg.

6. If you want to account NAT events (NEL):

   ```sh
   sysctl net.netflow.natevents=1
   ```

   Also make sure that conntrack events are enabled in your kernel by sysctl:

   ```sh
   sysctl net.netfilter.nf_conntrack_events=1
   ```


   Note that natevents feature is completely independent from traffic accounting
   (it's using so called conntrack events), thus you don't need to set or change
   any iptables rules to use that. You may need to enable kernel config option
   CONFIG_NF_CONNTRACK_EVENTS though (if it isn't already enabled).
   If you only need NEL and don't want to register NETFLOW xtables targets
   (for example on systems using nftables only), load module with:

   ```sh
   modprobe ipt_NETFLOW natevents=1 targets=0
   ```

   If you want full traffic accounting on a nftables-only system (not just
   NAT events), see the `hooks=` module parameter below, which captures
   packets directly on netfilter hooks without any iptables rules.

   For details on how they are exported for different protocol versions see
   below.

7. For SNMP support you will need to add this command into snmpd.conf to
   enable IPT-NETFLOW-MIB in SNMP agent:

   ```text
   dlmod netflow /usr/lib/snmp/dlmod/snmp_NETFLOW.so
   ```

   Restart snmpd for changes to take effect. Don't forget to properly configure
   access control. Example simplest configuration may looks like (note that this
   is whole /etc/snmp/snmpd.conf):

   ```text
   rocommunity public 127.0.0.1
   dlmod netflow /usr/lib/snmp/dlmod/snmp_NETFLOW.so
   ```

   Note, that this config will also allow _full_ read-only access to the whole
   linux MIB. To install IPT-NETFLOW-MIB locally, copy file IPT-NETFLOW-MIB.my
   into ~/.snmp/mibs/

   See the [detailed SNMP configuration example](https://github.com/nuclearcat/ipt-netflow/wiki/Configuring-SNMP-access).

   To check that MIB is installed well you may issue:

   ```sh
   snmptranslate -m IPT-NETFLOW-MIB -IR -Tp iptNetflowMIB
   ```

   This should output IPT-NETFLOW-MIB in tree form.

   To check that snmp agent is working well issue:

   ```sh
   snmpwalk -v 1 -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowMIB
   ```

   Should output full MIB. If MIB is not installed try:

   ```sh
   snmpget -v 1 -c public 127.0.0.1 .1.3.6.1.4.1.37476.9000.10.1.1.1.1.0
   ```

   Which should output STRING: "ipt_NETFLOW".

   MIB provides access to very similar statistics that you have in
   /proc/net/stat/ipt_netflow, you can read description of objects in
   text file IPT-NETFLOW-MIB.my

   If you want to access to SNMP stat in machine readable form for your
   scripts there is file /proc/net/stat/ipt_netflow_snmp

   Note: Using of SNMP v2c or v3 is mandatory for most tables, because
   this MIB uses 64-bit counters (Counter64) which is not supported in old
   SNMP v1. You should understand that 32-bit counter will wrap on 10Gbit
   traffic in just 3.4 seconds! So, always pass option `-v2c` or `-v3`
   to net-snmp utils. Or, for example, configure option `defVersion 2c`
   in ~/.snmp/snmp.conf. You can also have `defCommunity public` or v3
   auth parameters (defSecurityName, defSecurityLevel, defPassphrase)
   set there (man snmp.conf).

   Examples for dumping typical IPT-NETFLOW-MIB objects:

   - Module info (similar to modinfo, SNMPv1 is ok for following two objects):

     ```sh
     snmpwalk -v 1 -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowModule
     ```

   - Read-write sysctl-like parameters (yes, they are writable via snmpset, you
     may need to configure write access to snmpd, though):

     ```sh
     snmpwalk -v 1 -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowSysctl
     ```

   - Global performance stat of the module (note -v2c, because rest of the
     objects require SNMP v2c or SNMP v3):

     ```sh
     snmpwalk -v2c -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowTotals
     ```

   - Per-CPU (metering) and per-socket (exporting) statistics in table format:

     ```sh
     snmptable -v2c -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowCpuTable
     snmptable -v2c -c public 127.0.0.1 -m IPT-NETFLOW-MIB iptNetflowSockTable
     ```


## Options

Options can be passed as module parameters or changed dynamically through
`net.netflow` sysctls or `IPT-NETFLOW-MIB::iptNetflowSysctl`.

### `protocol=5`

Select NetFlow v5 (`5`), NetFlow v9 (`9`), or IPFIX (`10`). The default is
NetFlow v5. Use v9 or IPFIX when accounting for IPv6 traffic.

### `destination=HOST[:PORT]`

Set one or more collectors. The default port is 2055. Supported forms include:

- `destination=127.0.0.1:2055` — IPv4 collector.
- `destination=[2001:db8::1]:2055` — IPv6 collector. Brackets are optional if
  the port uses the `p` or `#` delimiter.
- `destination=127.0.0.1:2055,192.0.0.1:2055` — Mirror flows to multiple
  collectors.
- `destination=127.0.0.1:2055@127.0.0.2` — Bind to a source address.
- `destination=127.0.0.1:2055%eth0` — Bind to an interface.
- `destination=127.0.0.1:2055@127.0.0.2%eth0` — Bind to both a source address
  and an interface.

Separate entries with commas, spaces, semicolons, tabs, or newlines. Invalid
entries are logged and skipped while valid entries remain active. A destination
whose interface does not exist remains unconnected. The complete destination
string is limited to 255 characters.

### `sampler=MODE:N`

Enable flow sampling (RFC 7014), where `N` is a population size from 2 through
16383. This is flow sampling, not packet sampling (PSAMP). Set the value to `0`
or empty to disable it.

- `deterministic:N` — Select every Nth observed flow (systematic count-based
  sampling in IPFIX).
- `random:N` — Randomly select one out of N flows.
- `hash:N` — Select flows pseudo-randomly from their flow-key hash.

Deterministic and random sampling happen late in export processing, reducing
collector load but not module resource use. Hash sampling discards flows early,
reducing module CPU and memory use. All modes export the required sampling
metadata for NetFlow v5, v9, and IPFIX; hash sampling is reported to collectors
as random sampling.

### `natevents=1`

Collect NAT translation events as NetFlow Event Logging (NEL) for NetFlow
v9/IPFIX, or as dummy flows for NetFlow v5. The default is `0`.

For NetFlow v5 dummy flows:

- Source IP and port contain the pre-NAT source.
- Destination IP and port contain the post-NAT destination.
- Next hop and source AS contain the post-NAT source for SNAT.
- Next hop and destination AS contain the pre-NAT destination for DNAT.
- TCP flags contain SYN+ACK for start events and RST+FIN for stop events.
- Packet and traffic sizes are zero, so events do not affect accounting.

Compile this feature with `./configure --enable-natevents`. See the
[NAT logging draft](https://datatracker.ietf.org/doc/html/draft-ietf-behave-ipfix-nat-logging-04)
for the protocol details.

### `targets=1`

Register IPv4/IPv6 NETFLOW xtables targets (`-j NETFLOW`). Set this module-load
parameter to `0` with `natevents=1` for NAT-events-only operation. The default
is `1`.

### `hooks=0`

Capture packets directly on netfilter hooks without iptables rules. This is
useful on nftables-only systems. The bitmask values are:

| Bit | Hook | Traffic |
| ---: | --- | --- |
| 1 | PREROUTING | All incoming packets, including forwarded traffic |
| 2 | INPUT | Packets destined for the local host |
| 4 | FORWARD | Forwarded packets only |
| 8 | OUTPUT | Locally generated packets |
| 16 | POSTROUTING | All outgoing packets, including forwarded traffic |

The default is `0` (disabled). Both IPv4 and IPv6 hooks run after other
netfilter processing, so fwmarks set by nftables are visible. Because forwarded
packets traverse both PREROUTING and POSTROUTING, enabling both counts them
twice. To account for all traffic exactly once, use PREROUTING plus OUTPUT:

```sh
modprobe ipt_NETFLOW hooks=9 targets=0
```

Hooks are registered only in the initial network namespace. Hooks mode is
independent from `targets=` and `natevents=`; packets matching both a NETFLOW
rule and a hook are counted twice.

### `hooks_mark=0` and `hooks_mark_mask=0`

In hooks mode, account only packets matching:

```text
(skb->mark & hooks_mark_mask) == (hooks_mark & hooks_mark_mask)
```

A zero mask (the default) disables filtering. To restore per-rule selectivity
with nftables, mark selected traffic and match that mark in the module:

```sh
nft add rule inet filter forward ip saddr 10.0.0.0/8 meta mark set 0x1
modprobe ipt_NETFLOW hooks=9 hooks_mark=1 hooks_mark_mask=1 targets=0
```

### `inactive_timeout=15`

Export a flow after this many seconds of inactivity. The default is `15`.

### `active_timeout=1800`

Export a flow after this many seconds of activity. The default is `1800`
(30 minutes).

### `refresh-rate=20`

For NetFlow v9/IPFIX, resend templates after this many packets. The default is
`20`.

### `timeout-rate=30`

For NetFlow v9/IPFIX, resend old templates after this many minutes. The default
is `30`.

### `debug=0`

Set the debug level. The default is `0` (disabled).

### `sndbuf=number`

Set the output socket buffer size in bytes. Increase it if the module statistics
report packet drops as `sock: fail`. The default is the system socket-buffer
size.

### `hashsize=number`

Set the flow hash-table bucket count. For performance, a useful starting point
is at least twice the usual active-flow count. The default depends on system
memory.

### `maxflows=2000000`

Limit the number of simultaneously accounted flows to protect against resource
exhaustion. New flows are ignored after the limit is reached. The default is
2,000,000; zero means unlimited.

### `aggregation=RULES`

Apply comma-separated network and port aggregation rules, in definition order,
to both source and destination values. Network rules map a matching subnet to a
new prefix length, while port rules map a range to one port:

```text
aggregation=192.0.0.0/8=16,10.0.0.0/8=16,80-89=80,3128=80
```

The buffer is 1,024 bytes, while the sysctl interface limits input to roughly
700 bytes. Aggregation is enabled by default; use
`./configure --disable-aggregation` to omit it.

### `snmp-rules=RULES`

Convert interface names to SNMP indexes using comma-separated `name:base`
rules. For example, `ppp:200` maps `ppp11` to index 211. Rules are checked in
order; unmatched interfaces retain their kernel index. Keep the rule list short
because it is scanned without caching or hashing. Compile this feature with
`./configure --enable-snmp-rules`.

### `scan-min=1`

Set the minimum interval between flow-export scans, in kernel jiffies. Increase
it to reduce exporter CPU load.

### `promisc=1`

Enable promiscuous capture. See [README.promisc](README.promisc) for details.

### `exportcpu=number`

Pin the exporter to one CPU. This can keep exporting separate from CPUs handling
packet processing through RSS and affinity controls. Change it at runtime with:

```sh
echo number > /sys/module/ipt_NETFLOW/parameters/exportcpu
```

### `engine_id=number`

Set the IPFIX Observation Domain ID, NetFlow v9 Source ID, or NetFlow v5 Engine
ID so collectors can distinguish exporters. NetFlow v9/IPFIX use all 32 bits;
NetFlow v5 uses only the low 8 bits. The default is `0`. Change it at runtime
with:

```sh
echo number > /sys/module/ipt_NETFLOW/parameters/engine_id
```


## How to Read Statistics

  Statistics is your friend to fine tune and understand netflow module
  performance.

To see the statistics in human-readable form:

```sh
cat /proc/net/stat/ipt_netflow
```

  How to interpret the data:

> ipt_NETFLOW version v1.8-122-gfae9d59-dirty, srcversion 6141961152BE0DFA6A21EF4; aggr mac vlan

  This line helps to identify actual source that your module is build on.
  Please always supply it in all bug reports.

  v1.8-122: 1.8 is release, 122 is commit number after release;
  -gfae9d59: fae9d59 is short git commit id;
  -dirty: if present, meaning that git detected that sources are changed since
      last git commit, you may wish to do `git diff` to view changes;
  srcversion 6141961152BE0DFA6A21EF4: binary version of module, you can
      compare this with data from `modinfo ./ipt_NETFLOW.ko` to identify
      actual binary loaded;
  aggr mac vlan: tags to identify compile time options that are enabled.

> Protocol version 10 (ipfix), refresh-rate 20, timeout-rate 30, (templates 2, active 2). Timeouts: active 5, inactive 15. Maxflows 2000000

  Protocol version currently in use. Refresh-rate and timeout-rate
      for v9 and IPFIX. Total templates generated and currently active.
  Timeout: active X: how much seconds to wait before exporting active flow.
    - same as sysctl net.netflow.active_timeout variable.
  inactive X: how much seconds to wait before exporting inactive flow.
    - same as sysctl net.netflow.inactive_timeout variable.
  Maxflows 2000000: maxflows limit.
    - all flows above maxflows limit must be dropped.
    - you can control maxflows limit by sysctl net.netflow.maxflows variable.

> Promisc hack is disabled (observed 0 packets, discarded 0).

  observed n: To see that promisc hack is really working.

> Natevents disabled, count start 0, stop 0.

This shows whether NAT-events mode is enabled and how many start and stop events
have been reported.

> Flows: active 5187 (peak 83905 reached 0d0h1m ago), mem 283K, worker delay 100/1000 (37 ms, 0 us, 4:0 0 [3]).

  active X: currently active flows in memory cache.
    - for optimum CPU performance it is recommended to set hash table size to
      at least twice of average of this value, or higher.
  peak X reached Y ago: peak value of active flows.
  mem XK: how much kilobytes of memory currently taken by active flows.
    - one active flow taking 56 bytes of memory.
    - there is system limit on cache size too.
  worker delay X/HZ: how frequently exporter scan flows table per second.
  Rest is boring debug info.

> Hash: size 8192 (mem 32K), metric 1.00, [1.00, 1.00, 1.00]. InHash: 1420 pkt, 364 K, InPDU 28, 6716.

  Hash: size X: current hash size/limit.
    - you can control this by sysctl net.netflow.hashsize variable.
    - increasing this value can significantly reduce CPU load.
    - default value is not optimal for performance.
    - optimal value is twice of average of active flows.
  mem XK: how much memory occupied by hash table.
    - hash table is fixed size by nature, taking 4 bytes per entry.
  metric X, [X, X, X]: how optimal is your hash table being used.
    - lesser value mean more optimal hash table use, min is 1.0.
    - last three numbers in squares is moving average (EWMA) of hash table
      access divided by match rate (searches / matches) for 4sec, and 1, 5, and
      15 minutes. Sort of hash table load average. First value is instantaneous.
      You can try to increase hashsize if averages more than 1 (increase
      certainly if >= 2).
  InHash: X pkt, X K: how much traffic accounted for flows in the hash table.
  InPDU X, X: how much traffic in flows preparing to be exported.

> Rate: 202448 bits/sec, 83 packets/sec; 1 min: 668463 bps, 930 pps; 5 min: 329039 bps, 483 pps

  - Module throughput values for 1 second, 1 minute, and 5 minutes.

> cpu#  pps; <search found new [metric], trunc frag alloc maxflows>, traffic: <pkt, bytes>, drop: <pkt, bytes>
> cpu0  123; 980540  10473 180600 [1.03],    0    0    0    0, traffic: 188765, 14 MB, drop: 27863, 1142 K

  cpu#: this is Total and per CPU statistics for:
  pps: packets per second on this CPU. It's useful to debug load imbalance.
  <search found new, trunc frag alloc maxflows>: internal stat for:
  search found new: hash table searched, found, and not found counters.
  [metric]: one minute (ewma) average hash metric per cpu.
  trunc: how much truncated packets are ignored
    - for example if packets don't have valid IP header.
    - it's also accounted in drop packets counter, but not in drop bytes.
  frag: how much fragmented packets have seen.
    - kernel defragments INPUT/OUTPUT chains for us if nf_defrag_ipv[46]
      module is loaded.
    - these packets are not ignored but not reassembled either, so:
    - if there is no enough data in fragment (ex. tcp ports) it is considered
      to be zero.
  alloc: how much cache memory allocations are failed.
    - packets ignored and accounted in traffic drop stat.
    - probably increase system memory if this ever happen.
  maxflows: how much packets ignored on maxflows (maximum active flows reached).
    - packets ignored and accounted in traffic drop stat.
    - you can control maxflows limit by sysctl net.netflow.maxflows variable.

  traffic: <pkt, bytes>: how much traffic is accounted.
  pkt, bytes: sum of packets/megabytes accounted by module.
    - flows that failed to be exported (on socket error) is accounted here too.

  drop: <pkt, bytes>: how much of traffic is not accounted.
  pkt, bytes: sum of packets/kilobytes that are dropped by metering process.
    - reasons these drops are accounted here:
      truncated/fragmented packets,
      packet is for new flow but failed to allocate memory for it,
      packet is for new flow but maxflows is already reached.
    Traffic lost due to socket errors is not accounted here. Look below
      about export and socket errors.

> Export: Rate 0 bytes/s; Total 2 pkts, 0 MB, 18 flows; Errors 0 pkts; Traffic lost 0 pkts, 0 Kbytes, 0 flows.

  Rate X bytes/s: traffic rate generated by exporter itself.
  Total X pkts, X MB: total amount of traffic generated by exporter.
  X flows: how much data flows are exported.
  Errors X pkts: how much packets not sent due to socket errors.
  Traffic lost 0 pkts, 0 Kbytes, 0 flows: how much metered traffic is lost
    due to socket errors.
  Note that `cberr` errors are not accounted here due to their asynchronous
    nature. Read below about `cberr` errors.

> sock0: 10.0.0.2:2055 unconnected (1 attempts).

  If socket is unconnected (for example if module loaded before interfaces is
  up) it shows now much connection attempts was failed. It will try to connect
  until success.

> sock0: 10.0.0.2:2055, sndbuf 106496, filled 0, peak 106848; err: sndbuf reached 928, connect 0, cberr 0, other 0

  sockX: per destination stats for:
  X.X.X.X:Y: destination ip address and port.
    - controlled by sysctl net.netflow.destination variable.
  sndbuf X: how much data socket can hold in buffers.
    - controlled by sysctl net.netflow.sndbuf variable.
    - if you have packet drops due to sndbuf reached (error -11) increase this
      value.
  filled X: how much data in socket buffers right now.
  peak X: peak value of how much data in socket buffers was.
    - you will be interested to keep it below sndbuf value.
  err: how much packets are dropped due to errors.
    - all flows from them will be accounted in drop stat.
  sndbuf reached X: how much packets dropped due to sndbuf being too small
      (error -11).
  connect X: how much connection attempts was failed.
  cberr X: how much connection refused ICMP errors we got from export target.
    - probably you are not launched collector software on destination,
    - or specified wrong destination address.
    - flows lost in this fashion is not possible to account in drop stat.
    - these are ICMP errors, and would look like this in tcpdump:
      05:04:09.281247 IP alice.19440 > bob.2055: UDP, length 120
      05:04:09.281405 IP bob > alice: ICMP bob udp port 2055 unreachable, length 156
  other X: dropped due to other possible errors.

> aggr0: ...
  aggrX: aggregation rulesets.
    - controlled by sysctl net.netflow.aggregation variable.


## NetFlow Considerations

  List of all IPFIX Elements http://www.iana.org/assignments/ipfix/ipfix.xhtml

  Flow Keys are Elements that distinguish flows. Quoting RFC: "If a Flow
  Record for a specific Flow Key value already exists, the Flow Record is
  updated; otherwise, a new Flow Record is created."

  In this implementation following Elements are treated as Flow Keys:

     IPv4 source address:        sourceIPv4Address(8),
     IPv6 source address:        sourceIPv6Address(27),
     IPv4 destination address:   destinationIPv4Address(12),
     IPv6 destination address:   destinationIPv6Address(28),
     TCP/UDP source port:        sourceTransportPort(7),
     TCP/UDP destination port:   destinationTransportPort(11),
     input interface:            ingressInterface(10),
     IP protocol:                protocolIdentifier(4),
     IP TOS:                     ipClassOfService(5),
     and address family (IP or IPv6).

  Additional Flow Keys if VLAN exporting is enabled:

     First (outer) dot1q VLAN tag: dot1qVlanId(243) and
                                 dot1qPriority(244) for IPFIX,
                                 or vlanId(243) for NetFlow v9.
     Second (customer) dot1q VLAN tag: dot1qCustomerVlanId(245)
                                 and dot1qCustomerPriority(246).

  Additional Flow Keys if MAC address exporting is enabled:

     Destination MAC address:    destinationMacAddress(80),
     Source MAC address:         sourceMacAddress(56).

  Additional Flow Keys if MPLS-aware NetFlow is enabled:

     Captured MPLS stack is fully treated as flow key (including TTL values),
     which is Elements from mplsTopLabelStackSection(70) to
     mplsLabelStackSection10(79), and, if present, mplsTopLabelTTL(200).


  Other Elements are not Flow Keys. Note that outer interface, which is
  egressInterface(14), is not regarded as Flow Key. Quoting RFC 7012: "For
  Information Elements ... for which the value may change from packet to packet
  within a single Flow, the exported value of an Information Element is by
  default determined by the first packet observed for the corresponding Flow".

  Note that NetFlow and IPFIX modes of operation may have slightly different
  Elements being used and different statistics sent via Options Templates.


## Voila
