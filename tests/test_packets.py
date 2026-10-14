#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parents[1]
workspace = tempfile.TemporaryDirectory(prefix='ipt-netflow-test-')
out=Path(workspace.name)
src=(root/'ipt_NETFLOW.c').read_text()
if '--baseline' in sys.argv:
    src=subprocess.check_output(['git','show','f6133dd:ipt_NETFLOW.c'],cwd=root,text=True)
fn=src[src.index('static unsigned int netflow_target('):]
body=fn[fn.index('\n{')+2:fn.index('\ndo_protocols:')]
body=body.replace('return IPT_CONTINUE;', 'return (struct parsed){ .fragment = -1 };')
prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
union nf_inet_addr { uint32_t ip; struct in6_addr in6; };
struct ipt_netflow_tuple {
 union nf_inet_addr src,dst;
 uint16_t s_port,d_port,i_ifc;
 uint8_t protocol,tos,l3proto;
};
struct frag_hdr { uint8_t nexthdr,reserved; uint16_t frag_off; uint32_t identification; };
struct sk_buff { unsigned char data[128]; unsigned len,headlen; };
struct xt_action_param { int family; };
struct net_device { int ifindex; };
struct parsed { struct ipt_netflow_tuple tuple; int fragment; unsigned ptr; };
#define likely(x) (x)
#define unlikely(x) (x)
#define xt_family(p) ((p)->family)
#define if_in ((struct net_device *)0)
#define NETFLOW_STAT_INC(x) ((void)0)
#define NETFLOW_STAT_ADD(x,y) ((void)0)
#define NETFLOW_STAT_TS(x) ((void)0)
#define IP_OFFSET 0x1fff
#define NEXTHDR_NONE 59
#define SetXBit(x) (1U << (31-(x)))
#define SAVE_SPI(tuple,spi) { (tuple).s_port=(spi)>>16; (tuple).d_port=(spi); }
#define parse_l2_header(s,t) ((void)0)
#define ip4_options(p,s) 0
#define observed_hdrs(x) 0
#define ipv6_optlen(h) (((h)->hdrlen+1)<<3)
static int ipv6_ext_hdr(unsigned h) { return h==0 || h==43 || h==44 || h==51 || h==60; }
static void *skb_header_pointer(struct sk_buff *skb,unsigned offset,unsigned len,void *buffer)
{
 if (offset>skb->len || len>skb->len-offset) return NULL;
 if (offset+len<=skb->headlen) return skb->data+offset;
 memcpy(buffer,skb->data+offset,len);
 return buffer;
}
static struct parsed parse(struct sk_buff *skb,const struct xt_action_param *par)
{
'''
suffix=r'''
do_protocols:
 return (struct parsed){ .tuple=tuple, .fragment=fragment, .ptr=ptr };
}
int main(int argc,char **argv) {
 struct sk_buff skb={0};
 struct xt_action_param par={.family=AF_INET};
 struct parsed got;
 if (!strcmp(argv[1],"header")) {
  struct iphdr *ip=(void *)skb.data;
  ip->version=4; ip->ihl=5; ip->saddr=htonl(0x01020304);
  ip->daddr=htonl(0x05060708); ip->protocol=17; ip->tot_len=htons(20);
  skb.len=20;
  for (unsigned linear=0;linear<=20;linear++) {
   skb.headlen=linear; got=parse(&skb,&par);
   assert(got.tuple.src.ip==ip->saddr && got.tuple.dst.ip==ip->daddr);
   assert(got.tuple.protocol==17 && got.ptr==20);
  }
  par.family=AF_INET6; memset(&skb,0,sizeof(skb));
  struct ipv6hdr *ip6=(void *)skb.data;
  ip6->version=6; ip6->nexthdr=17; ip6->saddr.s6_addr[15]=7;
  skb.len=40;
  for(unsigned linear=0;linear<=40;linear++) {
   skb.headlen=linear; got=parse(&skb,&par);
   assert(got.tuple.src.in6.s6_addr[15]==7 && got.ptr==40);
  }
 } else if(!strcmp(argv[1],"ipv6")) {
  par.family=AF_INET6; skb.len=skb.headlen=64;
  struct ipv6hdr *ip6=(void *)skb.data;
  for(unsigned tc=0;tc<256;tc++) {
   ip6->priority=tc>>4; ip6->flow_lbl[0]=(tc&15)<<4; ip6->flow_lbl[1]=ip6->flow_lbl[2]=0;
   ip6->nexthdr=17; got=parse(&skb,&par); assert(got.tuple.tos==tc);
   assert(label(ip6)==0);
   ip6->flow_lbl[0]|=15;ip6->flow_lbl[1]=ip6->flow_lbl[2]=255;
   assert(label(ip6)==0xfffff);
  }
  ip6->nexthdr=44; skb.data[40]=60; skb.data[48]=17; skb.data[49]=0;
  struct frag_hdr *fh=(void *)(skb.data+40);
  fh->frag_off=htons(1); got=parse(&skb,&par);
  assert(!got.fragment && got.tuple.protocol==17 && got.ptr==56);
  fh->frag_off=0; got=parse(&skb,&par); assert(!got.fragment && got.tuple.protocol==17);
  fh->frag_off=htons(8); got=parse(&skb,&par); assert(got.fragment && got.tuple.protocol==60);
 } else {
  par.family=AF_INET6;
  struct ipv6hdr *ip=(void *)skb.data;
  ip->version=6; ip->nexthdr=51; skb.data[40]=17; skb.data[41]=0;
  for(unsigned n=2;n<8;n++) {
   skb.len=skb.headlen=40+n; got=parse(&skb,&par);
   assert(got.fragment && got.tuple.protocol==51);
  }
  skb.len=skb.headlen=48; skb.data[44]=0x12; skb.data[45]=0x34;
  skb.data[46]=0x56; skb.data[47]=0x78;
  got=parse(&skb,&par);
  assert(!got.fragment && got.tuple.protocol==17 && got.ptr==48);
  uint32_t spi; memcpy(&spi,skb.data+44,4);
  assert(got.tuple.s_port==(uint16_t)(spi>>16) && got.tuple.d_port==(uint16_t)spi);
 }
 puts("packet parser checks passed");
 return 0;
}
'''
expr=re.search(r'nf->flow_label = (.*?);',src,re.S).group(1)
helper='static unsigned label(const struct ipv6hdr *ip6) { union { struct ipv6hdr ip6; } *iph=(void *)ip6; return '+expr+'; }\n'
suffix=suffix.replace('int main(',helper+'int main(')
name='packet-baseline' if '--baseline' in sys.argv else 'packet-fixed'
(out/(name+'.c')).write_text(prefix+body+suffix)
subprocess.run(['gcc','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(out/(name+'.c')),'-o',str(out/name)],check=True)
for case in ('header','ah','ipv6'):
    result=subprocess.run([str(out/name),case],capture_output=True,text=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))
    print(case, 'PASS' if result.returncode==0 else 'FAIL',result.stdout,result.stderr[:2500])
    if result.returncode and '--baseline' not in sys.argv: sys.exit(1)
