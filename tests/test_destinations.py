#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise destination parsing, rollback, and allocation failures."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'ipt_NETFLOW.c').read_text()
compat = (root / 'compat.h').read_text()
start = compat.index('#define hex_to_bin compat_hex_to_bin')
inet = compat[start:compat.index('#endif /* IN6PTON_XDIGIT */', start)]
start = source.index('static size_t strncount(')
parser = source[start:source.index('\n#ifdef ENABLE_AGGR', start)]
def function(name, text=source):
    return re.search(r'^static[^\n]*\b' + name + r'\([^;]*?\n\{.*?^\}', text, re.M | re.S).group()
comparators = compat[compat.index('static int sockaddr_match_ipaddr6('):compat.index('\n#ifndef IN6PTON_XDIGIT')]

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
typedef uint8_t u8;
typedef uint16_t __be16;
#define KERN_ERR ""
#define printk(...) ((void)0)
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(n) struct list_head n={&n,&n}
#define list_empty(h) ((h)->next==(h))
#define list_entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_first_entry(h,t,m) list_entry((h)->next,t,m)
static void list_del(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;}
static void list_add_tail(struct list_head *n,struct list_head *h) {n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
struct ipt_netflow_sock {void *sock;struct list_head list;struct sockaddr_storage addr,saddr;char sdev[IFNAMSIZ];};
static LIST_HEAD(usock_list);
static int allocated,fail_at,attempts,connects;
static void *vmalloc(size_t size) {if(++attempts==fail_at)return NULL;allocated++;return malloc(size);}
static void vfree(void *p) {if(p){allocated--;free(p);}}
static void destination_removeall(void) {
 while(!list_empty(&usock_list)) {
  struct ipt_netflow_sock *s=list_first_entry(&usock_list,struct ipt_netflow_sock,list);
  list_del(&s->list);vfree(s);
 }
}
static void usock_connect(struct ipt_netflow_sock *s,int send) {connects++;}
#define ipv6_addr_equal(a,b) (!memcmp(a,b,sizeof(*(a))))
#define mutex_lock(p) ((void)0)
#define mutex_unlock(p) ((void)0)
#define list_for_each_entry(p,h,m) for(p=list_entry((h)->next,__typeof__(*p),m);&p->m!=(h);p=list_entry(p->m.next,__typeof__(*p),m))
#define KERN_INFO ""
static void usock_close_free(struct ipt_netflow_sock *s) {vfree(s);}

'''
code += comparators + function('is_zero_addr') + function('add_usock') + '\n' + inet + parser + r'''
int main(void) {
 const char *valid[]={"127.0.0.1","127.0.0.1:1","127.0.0.1:65535",
  "127.0.0.1:0x807@127.0.0.2%eth0","[2001:db8::1]:2055","2001:db8::1p2055",
  "2001:db8::1#2055","[::1]","[fe80::1]:2055@fe80::2%eth0","::ffff:127.0.0.1"};
 for(unsigned i=0;i<sizeof(valid)/sizeof(*valid);i++) {
  assert(!add_destinations(valid[i]));assert(allocated==1);
  struct ipt_netflow_sock *s=list_first_entry(&usock_list,struct ipt_netflow_sock,list);
  unsigned port=s->addr.ss_family==AF_INET?ntohs(((struct sockaddr_in *)&s->addr)->sin_port):ntohs(((struct sockaddr_in6 *)&s->addr)->sin6_port);
  assert(port==(i==1?1:i==2?65535:2055));
 }
 const char *bad[]={"127.0.0.1:0","127.0.0.1:65536","127.0.0.1:","127.0.0.1:2055xyz",
  "127.0.0.1/24","[2001:db8::1","[::1]:","[::1]:65536","[::1]:0","[::1]garbage",
  "127.0.0.1:18446744073709553671","127.0.0.1:0x100000807","127.0.0.1%",
  "127.0.0.1%0123456789012345","127.0.0.1@","[::1]@nope","127.0.0.1:2055@127.0.0.2/24",
  "127.0.0.1:2055,invalid","invalid", "127.0.0.1:08"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
  void *old=usock_list.next;int n=connects;
  assert(add_destinations(bad[i])==-EINVAL);
  assert(usock_list.next==old && allocated==1 && connects==n);
 }
 for(unsigned i=1;i<=2;i++) {
  fail_at=attempts+i;void *old=usock_list.next;int n=connects;
  assert(add_destinations("127.0.0.2,127.0.0.3")==-ENOMEM);
  assert(allocated==1 && usock_list.next==old && connects==n);
 }
 fail_at=0;assert(!add_destinations("127.0.0.2; [::1]:2055\t127.0.0.3"));assert(allocated==3);
 assert(!add_destinations("[fe80::1]:2055%eth0,[fe80::1]:2055%eth1,[fe80::1]:2055%eth0"));assert(allocated==2);
 assert(!add_destinations("127.0.0.1@127.0.0.2,127.0.0.1@127.0.0.3,127.0.0.1@127.0.0.2"));assert(allocated==2);
 assert(!add_destinations("127.0.0.1,127.0.0.1@0.0.0.0"));assert(allocated==1);
 assert(!add_destinations(""));assert(!allocated && list_empty(&usock_list));
 puts("destination validation and rollback checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'destinations.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'destinations.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
