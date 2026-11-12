#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise VLAN decapsulation with truncated and nonlinear skb substitutes."""
from pathlib import Path
import os
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'ipt_NETFLOW.c').read_text()
start = source.index('static __be16 __skb_network_protocol(')
end = source.index('\nstatic struct packet_type promisc_packet_type', start)
code = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#undef htons
#define htons(x) __builtin_bswap16(x)
#endif
typedef uint16_t __be16;
#define ETH_P_TEB 0x6558
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define ETH_P_IP 0x800
#define ETH_P_IPV6 0x86dd
#define ETH_HLEN 14
#define VLAN_HLEN 4
#define PACKET_OTHERHOST 3
#define GFP_ATOMIC 0
#define NETFLOW_STAT_INC(x) ((void)0)
#define WARN_ON(x) (x)
#define unlikely(x) (x)
#define cpu_to_be16(x) htons(x)
struct ethhdr {unsigned char addresses[12];__be16 h_proto;};
struct vlan_hdr {__be16 tci,h_vlan_encapsulated_proto;};
struct sk_buff {unsigned char storage[64],*data;unsigned len,linear,mac_len;__be16 protocol;int pkt_type;};
struct net_device {};
struct packet_type {};
static int dropped,received;
#define skb_mac_header(s) ((s)->storage)
static int pskb_may_pull(struct sk_buff *s,unsigned n) {
 if(n>s->len)return 0;
 if(s->linear<n)s->linear=n;
 return 1;
}
static void skb_push(struct sk_buff *s,unsigned n) {s->data-=n;s->len+=n;s->linear+=n;}
static void skb_pull(struct sk_buff *s,unsigned n) {assert(n<=s->len && n<=s->linear);s->data+=n;s->len-=n;s->linear-=n;}
#define skb_share_check(s,g) (s)
#define skb_reset_network_header(s) ((void)0)
#define skb_reset_mac_len(s) ((void)0)
#define kfree_skb(s) (dropped++)
#define promisc4_rcv(s,d,p,o) (received++,0)
#define promisc6_rcv(s,d,p,o) (received++,0)
'''
code += source[start:end] + r'''
int main(void) {
 for(unsigned tags=1;tags<=2;tags++)for(unsigned len=14;len<=14+4*tags;len++) {
  struct sk_buff s={.len=len-14,.mac_len=18,.protocol=htons(ETH_P_8021Q),.pkt_type=PACKET_OTHERHOST};
  s.data=s.storage+14;
  for(unsigned i=0;i<tags;i++) {
   struct vlan_hdr *vh=(void *)(s.storage+14+4*i);
   vh->h_vlan_encapsulated_proto=htons(i+1==tags?ETH_P_IP:ETH_P_8021AD);
  }
  dropped=received=0;
  promisc_rcv(&s,NULL,NULL,NULL);
  assert(dropped==(len<14+4*tags) && received==(len==14+4*tags));
 }
 struct sk_buff s={.mac_len=32,.protocol=htons(ETH_P_8021Q),.pkt_type=PACKET_OTHERHOST};
 s.data=s.storage+14;dropped=received=0;
 promisc_rcv(&s,NULL,NULL,NULL);assert(dropped==1 && !received);
 puts("promiscuous VLAN checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'promisc.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'promisc.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
