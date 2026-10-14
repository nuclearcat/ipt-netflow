#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os
import subprocess
import tempfile

root=Path(__file__).resolve().parents[1]
workspace = tempfile.TemporaryDirectory(prefix='ipt-netflow-test-')
out=Path(workspace.name)
src=(root/'ipt_NETFLOW.c').read_text()
body=src[src.index('static void aggregation_remove(struct list_head *list)\n{'):src.index('\n#endif',src.index('static void aggregation_remove(struct list_head *list)\n{'))]
prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <arpa/inet.h>
typedef uint32_t __be32;
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&n,&n}
#define list_entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_empty(h) ((h)->next==(h))
#define list_for_each_entry_safe(p,n,h,m) for(p=list_entry((h)->next,__typeof__(*p),m),n=list_entry(p->m.next,__typeof__(*p),m); &p->m!=(h);p=n,n=list_entry(n->m.next,__typeof__(*n),m))
static void list_del(struct list_head *n) { n->prev->next=n->next; n->next->prev=n->prev; }
static void list_add_tail(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
static void list_move_tail(struct list_head *n,struct list_head *h) {list_del(n);list_add_tail(n,h);}
static void list_move(struct list_head *n,struct list_head *h) {list_del(n);n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
struct netflow_aggr_n {struct list_head list;unsigned usage;uint32_t mask,addr,aggr_mask;uint8_t prefix;};
struct netflow_aggr_p {struct list_head list;unsigned usage;uint16_t port1,port2,aggr_port;};
static LIST_HEAD(aggr_n_list);
static LIST_HEAD(aggr_p_list);
#define write_lock_bh(x) ((void)0)
#define write_unlock_bh(x) ((void)0)
#define KERN_ERR ""
#define KERN_INFO ""
#define printk(...) ((void)0)
#define SEPARATORS ",; \t\n"
static int live,attempt,fail_at;
static void *vmalloc(size_t n) {if(++attempt==fail_at) return NULL;void *p=malloc(n);if(p)live++;return p;}
static void vfree(void *p) {live--;free(p);}
static __be32 bits2mask(int bits) {return bits?0xffffffffU<<(32-bits):0;}
'''
suffix=r'''
int main(void) {
 char good[]="10.0.0.0/8=16,80-89=80,3128=80,";
 assert(add_aggregation(good)==0 && live==3);
 struct netflow_aggr_p *last=list_entry(aggr_p_list.prev,struct netflow_aggr_p,list);
 assert(last->port1==3128 && last->port2==3128 && last->aggr_port==80);
 const char *bad[]={"10.0.0.0/33=8","10.0.0.0/8=33","65536=80","1=65536","90-80=80","bad"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
  char input[100];strcpy(input,bad[i]);assert(add_aggregation(input)==-EINVAL && live==3);
 }
 char partial[]="1.0.0.0/8=16,80=80";
 attempt=0;fail_at=2;
 assert(add_aggregation(partial)==-ENOMEM && live==3);
 fail_at=0;
 char partial_bad[]="1.0.0.0/8=16,80=70000";
 assert(add_aggregation(partial_bad)==-EINVAL && live==3);
 char empty[]="";
 assert(add_aggregation(empty)==0 && live==0);
 puts("aggregation validation, rollback and allocation failure checks passed");
}
'''
(out/'aggregation.c').write_text(prefix+body+suffix)
subprocess.run(['gcc','-g','-O1','-fsanitize=address,undefined',str(out/'aggregation.c'),'-o',str(out/'aggregation')],check=True)
subprocess.run([str(out/'aggregation')],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0'))
