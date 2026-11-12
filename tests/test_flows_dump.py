#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise production seq iteration with failed clone allocations and seeks."""
from pathlib import Path
import os
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'ipt_NETFLOW.c').read_text()
start = source.index('struct flows_dump_private {')
end = source.index('\nstatic void flows_dump_seq_stop', start)
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(h) ((h)->next=(h)->prev=(h))
#define list_entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_empty(h) ((h)->next==(h))
#define list_is_last(p,h) ((p)->next==(h))
#define list_for_each_entry(p,h,m) for(p=list_entry((h)->next,__typeof__(*p),m);&p->m!=(h);p=list_entry(p->m.next,__typeof__(*p),m))
#define list_for_each_entry_safe(p,t,h,m) for(p=list_entry((h)->next,__typeof__(*p),m),t=list_entry(p->m.next,__typeof__(*p),m);&p->m!=(h);p=t,t=list_entry(t->m.next,__typeof__(*t),m))
static void list_add(struct list_head *n,struct list_head *h) {n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
struct ipt_netflow {int id;struct list_head flows_list;};
#define LOCK_COUNT 3
struct stripe_entry {int lock;unsigned size,offset;struct list_head list;} htable_stripes[LOCK_COUNT];
struct seq_file {void *private;};
#define SEQ_START_TOKEN ((void *)1)
#define GFP_ATOMIC 0
#define spin_lock_bh(p) ((void)0)
#define spin_unlock_bh(p) ((void)0)
static void *ipt_netflow_cachep;
static int fail_alloc;
static void *kmem_cache_alloc(void *p,int g) {if(fail_alloc>0){fail_alloc--;return NULL;}return malloc(sizeof(struct ipt_netflow));}
#define kmem_cache_free(c,p) free(p)
'''
code += source[start:end] + r'''
int main(void) {
 struct flows_dump_private st={0};struct seq_file seq={&st};
 struct ipt_netflow f[2]={{.id=1},{.id=2}};
 INIT_LIST_HEAD(&st.list);
 for(int i=0;i<LOCK_COUNT;i++)INIT_LIST_HEAD(&htable_stripes[i].list);
 list_add(&f[0].flows_list,&htable_stripes[0].list);
 list_add(&f[1].flows_list,&htable_stripes[2].list);
 fail_alloc=1;
 struct list_head *n=nf_get_stripe(&st,0);
 assert(n && n!=&st.list && list_entry(n,struct ipt_netflow,flows_list)->id==2);
 assert(st.alloc_errors==1 && st.stripe==2);
 assert(!nf_get_next(&st,n));assert(!nf_get_next(&st,NULL));
 fail_alloc=2;assert(!nf_get_stripe(&st,0));assert(list_empty(&st.list));
 for(unsigned i=0;i<3;i++) {
  loff_t pos=i==0?100:((loff_t)1<<32)+i;
  assert(!flows_dump_seq_start(&seq,&pos));assert(st.pcache==pos);
 }
 loff_t pos=0;assert(flows_dump_seq_start(&seq,&pos)==SEQ_START_TOKEN);
 n=flows_dump_seq_next(&seq,SEQ_START_TOKEN,&pos);
 assert(n && list_entry(n,struct ipt_netflow,flows_list)->id==1);
 n=flows_dump_seq_next(&seq,n,&pos);
 assert(n && list_entry(n,struct ipt_netflow,flows_list)->id==2);
 assert(!flows_dump_seq_next(&seq,n,&pos));
 nf_free_stripe(&st.list);
 puts("flow dump allocation and seek checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'dump.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'dump.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'), timeout=10)
