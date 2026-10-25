#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise production table lookup/resize/scan code with pthread stripe locks."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
src = (root / 'ipt_NETFLOW.c').read_text()
start = src.index('#define LOCK_COUNT ')
stripes = src[start:src.index('\n#ifdef HAVE_LLIST', start)]
start = src.index('#ifdef SAMPLING_HASH\nstatic uint32_t hash_seed;')
helpers = src[start:src.index('\nstatic struct ipt_netflow *\nipt_netflow_alloc', start)]
start = src.index('static int hsize_procctl(')
sysctl = src[start:src.index('\nstatic int sndbuf_procctl(', start)]
start = src.index('#ifdef SAMPLING_HASH\n\thash = __hash_netflow(&tuple);')
lookup = src[start:src.index('\n\tif (unlikely(!nf))', start)]
start = src.index('\tfor (i = 0; i < LOCK_COUNT; i++) {\n\t\tspin_lock_init')
init = src[start:src.index('\n\t}\n', start) + len('\n\t}\n')]
start = src.index('\tfor (i = 0; i < LOCK_COUNT; i++) {', src.index('static int netflow_scan_and_export(const int flush)\n{'))
scan = src[start:src.index('\n#ifdef HAVE_LLIST', start)]
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#define __read_mostly
#define ____cacheline_aligned_in_smp
#define fallthrough __attribute__((fallthrough))
#define likely(x) (x)
#define unlikely(x) (x)
#define KERN_ERR ""
#define KERN_INFO ""
#define printk(...) ((void)0)
#define NETFLOW_STAT_INC(x) ((void)0)
static pthread_mutex_t htable_mutex;
static _Thread_local unsigned resize_lock_depth;
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) do {assert(!pthread_mutex_lock(p));if((p)==&htable_mutex)resize_lock_depth++;} while(0)
#define mutex_unlock(p) do {if((p)==&htable_mutex){assert(resize_lock_depth==1);resize_lock_depth--;}assert(!pthread_mutex_unlock(p));} while(0)
typedef struct ctl_table {void *data;} ctl_table_no_const;
#define PROC_CTL_TABLE struct ctl_table
#define BEFORE2632(a,b)
#define __user
static int parse_error,requested_size,proc_calls;
static int proc_dointvec(struct ctl_table *ctl,int write,void *buf,size_t *len,loff_t *pos) {
 proc_calls++;
 if(parse_error)return parse_error;
 if(write && *len) *(int *)ctl->data=requested_size;
 return 0;
}
typedef pthread_mutex_t spinlock_t;
static _Thread_local unsigned bh_depth;
static void spin_lock_init(spinlock_t *p) {assert(!pthread_mutex_init(p,NULL));}
static void spin_lock_bh(spinlock_t *p) {assert(!bh_depth++);mutex_lock(p);}
static void spin_unlock_bh(spinlock_t *p) {assert(bh_depth--==1);mutex_unlock(p);}
static int spin_trylock_bh(spinlock_t *p) {assert(!bh_depth);if(pthread_mutex_trylock(p))return 0;bh_depth++;return 1;}
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(h) ((h)->next=(h)->prev=(h))
#define LIST_HEAD(n) struct list_head n={&n,&n}
#define list_entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_empty(h) ((h)->next==(h))
#define list_for_each_entry(p,h,m) for(p=list_entry((h)->next,__typeof__(*p),m);&p->m!=(h);p=list_entry(p->m.next,__typeof__(*p),m))
#define list_for_each_entry_safe_reverse(p,t,h,m) for(p=list_entry((h)->prev,__typeof__(*p),m),t=list_entry(p->m.prev,__typeof__(*p),m);&p->m!=(h);p=t,t=list_entry(t->m.prev,__typeof__(*t),m))
static void list_del(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;}
static void list_add(struct list_head *n,struct list_head *h) {n->next=h->next;n->prev=h;h->next->prev=n;h->next=n;}
struct hlist_node {struct hlist_node *next,**pprev;};
struct hlist_head {struct hlist_node *first;};
#define INIT_HLIST_HEAD(h) ((h)->first=NULL)
#define compat_hlist_for_each_entry(p,pos,h,m) for(struct hlist_node *node=(h)->first;node && ((p)=list_entry(node,__typeof__(*p),m),1);node=node->next)
static void hlist_del(struct hlist_node *n) {*n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;n->next=NULL;n->pprev=NULL;}
static void hlist_add_head(struct hlist_node *n,struct hlist_head *h) {n->next=h->first;if(n->next)n->next->pprev=&n->next;n->pprev=&h->first;h->first=n;}
struct ipt_netflow_tuple {uint32_t id;};
struct ipt_netflow {struct hlist_node hlist;struct list_head flows_list;struct ipt_netflow_tuple tuple;uint64_t nr_bytes,nr_packets;};
#define ipt_netflow_tuple_equal(a,b) ((a)->id==(b)->id)
#define FLOW_FULL_WATERMARK UINT64_MAX
static atomic_int fail_alloc,live_tables,peak_tables;
static int expect_resize_lock;
static void *vmalloc(size_t size) {
 if(expect_resize_lock)assert(resize_lock_depth==1);
 if(atomic_exchange(&fail_alloc,0))return NULL;
 void *p=malloc(size);
 if(p) {
  int live=++live_tables,peak=peak_tables;
  while(live>peak && !atomic_compare_exchange_weak(&peak_tables,&peak,live)) {}
 }
 return p;
}
static void vfree(void *p) {if(p){live_tables--;free(p);}}
#include "murmur3.h"
struct sampling {unsigned mode,interval;};
static struct sampling samp;
#define SAMPLER_HASH 3
#define IPT_CONTINUE 0
typedef uint32_t u32;
typedef uint64_t u64;
'''
account = r'''
static atomic_ullong accounted,exported,accounted_bytes,exported_bytes;
static unsigned int account(uint32_t id) {
 struct ipt_netflow_tuple tuple={id};
 struct stripe_entry *stripe;
 struct ipt_netflow *nf;
 uint32_t hash;
'''
account_end = r'''
 if(!nf) {
  nf=calloc(1,sizeof(*nf));assert(nf);nf->tuple=tuple;
  hlist_add_head(&nf->hlist,&stripe->hash[hash]);
  list_add(&nf->flows_list,&stripe->list);
 }
 unsigned bytes=40+id%1500;
 nf->nr_bytes+=bytes;nf->nr_packets++;
 atomic_fetch_add(&accounted,1);
 atomic_fetch_add(&accounted_bytes,bytes);
 spin_unlock_bh(&stripe->lock);
 assert(!bh_depth);
 return 0;
}
#define STEADY 2048
static _Thread_local unsigned wk_trylock,wk_count;
#define jiffies 0
#define needs_export_rec(nf,i,a,j) ((nf)->tuple.id>=STEADY)
static void export_scan(void) {
 int i;
 struct ipt_netflow *nf,*tmp;
 LIST_HEAD(export_list);
'''
scan_end = r'''
 while(!list_empty(&export_list)) {
  nf=list_entry(export_list.next,struct ipt_netflow,flows_list);
  list_del(&nf->flows_list);atomic_fetch_add(&exported,nf->nr_packets);
  atomic_fetch_add(&exported_bytes,nf->nr_bytes);free(nf);
 }
 assert(!bh_depth);
}
'''
suffix = r'''
static void verify(void) {
 unsigned count=0;uint64_t bytes=0,packets=0;
 struct hlist_head *buckets=htable;
 for(unsigned i=0;i<LOCK_COUNT;i++) {
  struct stripe_entry *s=&htable_stripes[i];
  assert(s->hash==buckets && s->offset==(unsigned)(buckets-htable) && s->size);
  unsigned listed=0,hashed=0;
  struct ipt_netflow *nf;
  list_for_each_entry(nf,&s->list,flows_list) {
   uint32_t hash=__hash_netflow(&nf->tuple);
   assert((hash&LOCK_COUNT_MASK)==i);
   assert(ipt_netflow_find(&nf->tuple,&s->hash[stripe_hash(s,hash)])==nf);
   bytes+=nf->nr_bytes;packets+=nf->nr_packets;listed++;
  }
  for(unsigned j=0;j<s->size;j++) {
   struct hlist_node **prev=&s->hash[j].first;
   for(struct hlist_node *n=*prev;n;n=n->next) {
    assert(n->pprev==prev);prev=&n->next;hashed++;
   }
  }
  assert(listed==hashed);count+=listed;buckets+=s->size;
 }
 assert(buckets==htable+htable_size && count>=STEADY);
 assert(packets+exported==accounted && bytes+exported_bytes==accounted_bytes);
 assert(live_tables==1);
}
static uint64_t order(void) {
 uint64_t result=0;
 for(unsigned i=0;i<LOCK_COUNT;i++) {
  struct ipt_netflow *nf;
  list_for_each_entry(nf,&htable_stripes[i].list,flows_list)
   result=result*1099511628211ULL+nf->tuple.id;
 }
 return result;
}
static atomic_int stop;
static pthread_barrier_t start_workers;
static void *packets(void *arg) {
 pthread_barrier_wait(&start_workers);
 uint32_t state=(uintptr_t)arg+1;
 for(unsigned i=0;i<50000;i++) {
  state=state*1664525+1013904223;account(state%(STEADY+1024));
 }
 return NULL;
}
static void *resizer(void *arg) {
 pthread_barrier_wait(&start_workers);
 static const int sizes[]={256,257,511,512,513,1021,4096,65537,768};
 for(unsigned i=0;i<150;i++) assert(!set_hashsize(sizes[(i+(uintptr_t)arg)%9]));
 return NULL;
}
static void *scanner(void *unused) {
 pthread_barrier_wait(&start_workers);
 while(!stop){export_scan();sched_yield();}return NULL;
}
int main(void) {
 int i;
#ifdef SAMPLING_HASH
 hash_seed=0x12345678;
#endif
 htable_size=1021;htable=alloc_hashtable(htable_size);assert(htable);
'''
end = r'''
 expect_resize_lock=1;
 for(unsigned id=0;id<STEADY;id++) account(id);
 verify();
#ifdef SAMPLING_HASH
 samp=(struct sampling){SAMPLER_HASH,4};
 for(unsigned id=0;id<STEADY;id++) {
  struct ipt_netflow_tuple tuple={id};
  uint64_t before=accounted;
  account(id);
  assert(accounted==before+!((u32)(((u64)__hash_netflow(&tuple)*samp.interval)>>32)));
 }
 samp.mode=0;
#endif
 uint64_t original_order=order();
 const int sizes[]={256,257,511,512,513,65537,1021,1};
 for(unsigned n=0;n<sizeof(sizes)/sizeof(*sizes);n++) {
  assert(!set_hashsize(sizes[n]));verify();assert(order()==original_order);
 }
 struct hlist_head *old=htable;unsigned oldsize=htable_size;
 struct ctl_table ctl={&htable_size};size_t len=1;loff_t pos=0;
 parse_error=-EINVAL;requested_size=65537;
 assert(hsize_procctl(&ctl,1,NULL,&len,&pos)==-EINVAL && htable==old);
 parse_error=0;requested_size=255;
 assert(hsize_procctl(&ctl,1,NULL,&len,&pos)==-EPERM && htable==old);
 requested_size=257;
 assert(!hsize_procctl(&ctl,0,NULL,&len,&pos) && htable==old);
 /* Neither no-op path may allocate, even under allocation pressure. */
 fail_alloc=1;requested_size=htable_size;
 assert(!hsize_procctl(&ctl,1,NULL,&len,&pos) && htable==old && fail_alloc==1);
 assert(!set_hashsize(htable_size) && htable==old && fail_alloc==1);
 int calls=proc_calls;len=0;requested_size=65537;
 assert(!hsize_procctl(&ctl,1,NULL,&len,&pos) && htable==old && fail_alloc==1);
 assert(proc_calls==calls);len=1;
 fail_alloc=1;
 assert(set_hashsize(1024)==-ENOMEM && htable==old && htable_size==oldsize);
 verify();
 pthread_t workers[4],resize[2],scan_thread;
 assert(!pthread_barrier_init(&start_workers,NULL,7));
 assert(!pthread_create(&scan_thread,NULL,scanner,NULL));
 for(uintptr_t n=0;n<2;n++) assert(!pthread_create(&resize[n],NULL,resizer,(void *)n));
 for(uintptr_t n=0;n<4;n++) assert(!pthread_create(&workers[n],NULL,packets,(void *)n));
 for(unsigned n=0;n<4;n++) assert(!pthread_join(workers[n],NULL));
 for(unsigned n=0;n<2;n++) assert(!pthread_join(resize[n],NULL));
 stop=1;assert(!pthread_join(scan_thread,NULL));
 assert(peak_tables==2);
 assert(!pthread_barrier_destroy(&start_workers));
 verify();export_scan();verify();
 for(unsigned n=0;n<LOCK_COUNT;n++) {
  struct stripe_entry *s=&htable_stripes[n];
  while(!list_empty(&s->list)) {
   struct ipt_netflow *nf=list_entry(s->list.next,struct ipt_netflow,flows_list);
   list_del(&nf->flows_list);hlist_del(&nf->hlist);free(nf);
  }
  assert(!pthread_mutex_destroy(&s->lock));
 }
 vfree(htable);assert(!live_tables);
 puts("striped lookup, resize, order, rollback and concurrent packet/export checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    out = Path(tmp)
    code = prefix + stripes + helpers + sysctl + account + lookup + account_end + scan + scan_end + suffix + init + end
    (out / 'hashtable.c').write_text(code)
    for options in ([], ['-DSAMPLING_HASH']):
        subprocess.run(['gcc', '-g', '-O1', '-pthread', '-fsanitize=address,undefined',
                        '-I', str(root), *options, str(out / 'hashtable.c'),
                        '-o', str(out / 'hashtable')], check=True)
        subprocess.run([str(out / 'hashtable')], check=True, timeout=60,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
