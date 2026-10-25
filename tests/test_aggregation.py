#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
workspace = tempfile.TemporaryDirectory(prefix='ipt-netflow-test-')
out = Path(workspace.name)
src = (root / 'ipt_NETFLOW.c').read_text()
start = src.index('static void aggregation_remove(struct list_head *list)\n{')
body = src[start:src.index('\n#endif', start)]
start = src.index('static int aggregation_procctl(')
handler = src[start:src.index('\n#endif', start)]
start = src.index('\t/* aggregate networks */', src.index('static unsigned int netflow_target('))
packet = src[start:src.index('\n#endif', start)]
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
typedef uint32_t __be32;
struct list_head { struct list_head *next,*prev; };
#define INIT_LIST_HEAD(h) ((h)->next=(h)->prev=(h))
#define list_entry(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_empty(h) ((h)->next==(h))
#define list_for_each_entry(p,h,m) for(p=list_entry((h)->next,__typeof__(*p),m); &p->m!=(h);p=list_entry(p->m.next,__typeof__(*p),m))
static void list_del(struct list_head *n) { n->prev->next=n->next; n->next->prev=n->prev; }
static void list_add_tail(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
struct netflow_aggr_n {struct list_head list;atomic_uint usage;uint32_t mask,addr,aggr_mask;uint8_t prefix;};
struct netflow_aggr_p {struct list_head list;atomic_uint usage;uint16_t port1,port2,aggr_port;};
struct aggregation_rules {struct list_head nets,ports;};
static _Atomic(struct aggregation_rules *) aggr_ruleset;
static pthread_mutex_t aggr_config_lock=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned config_lock_depth;
#define mutex_lock(x) do {assert(!pthread_mutex_lock(x));assert(!config_lock_depth++);} while(0)
#define mutex_unlock(x) do {assert(config_lock_depth--==1);assert(!pthread_mutex_unlock(x));} while(0)
#define lockdep_is_held(x) (config_lock_depth==1)
/* Model the grace-period lifetime contract, not the kernel RCU implementation. */
static pthread_rwlock_t readers=PTHREAD_RWLOCK_INITIALIZER;
#define rcu_read_lock() assert(!pthread_rwlock_rdlock(&readers))
#define rcu_read_unlock() assert(!pthread_rwlock_unlock(&readers))
#define rcu_assign_pointer(p,v) atomic_store_explicit(&(p),v,memory_order_release)
#define rcu_dereference(p) atomic_load_explicit(&(p),memory_order_acquire)
#define rcu_dereference_protected(p,c) (assert(c),rcu_dereference(p))
static void synchronize_rcu(void) { assert(!pthread_rwlock_wrlock(&readers));assert(!pthread_rwlock_unlock(&readers)); }
#define atomic_inc(p) atomic_fetch_add(p,1)
#define unlikely(x) (x)
#define KERN_ERR ""
#define KERN_INFO ""
#define printk(...) ((void)0)
#define SEPARATORS ",; \t\n"
static atomic_int live,attempt,fail_at;
static void *vmalloc(size_t n) {if(++attempt==fail_at) return NULL;void *p=malloc(n);if(p)live++;return p;}
static void vfree(void *p) {if(p){live--;free(p);}}
#define GFP_KERNEL 0
#define kmalloc(n,f) vmalloc(n)
#define kfree(p) vfree(p)
typedef struct ctl_table {void *data;size_t maxlen;} ctl_table_no_const;
#define PROC_CTL_TABLE struct ctl_table
#define BEFORE2632(a,b)
#define __user
static char aggregation_buf[1024];
static int debug,string_error;
static int proc_dostring(struct ctl_table *ctl,int write,void *buf,size_t *len,loff_t *pos) {
 if(string_error)return string_error;
 if(write) {
  size_t n=strcspn(buf,"\n");if(n>*len)n=*len;
  if(n>=ctl->maxlen)n=ctl->maxlen-1;
  memcpy(ctl->data,buf,n);((char *)ctl->data)[n]=0;
 } else {
  size_t n=strlen(ctl->data);if(n>*len)n=*len;
  memcpy(buf,ctl->data,n);*len=n;
 }
 *pos+=*len;return 0;
}
static __be32 bits2mask(int bits) {return bits?0xffffffffU<<(32-bits):0;}
'''
apply = r'''
struct result {uint32_t src,dst;uint16_t sport,dport;uint8_t smask,dmask;};
static struct result apply(int family, int protocol) {
 const struct aggregation_rules *aggr_rules;
 struct netflow_aggr_n *aggr_n;
 struct netflow_aggr_p *aggr_p;
 uint8_t s_mask=0,d_mask=0;
 struct {struct {uint32_t ip;} src,dst;uint16_t s_port,d_port;int protocol;} tuple={
  .src.ip=htonl(0x0a010203),.dst.ip=htonl(0x0a020304),
  .s_port=htons(81),.d_port=htons(3128),.protocol=protocol};
'''
apply_end = r'''
 return (struct result){ntohl(tuple.src.ip),ntohl(tuple.dst.ip),ntohs(tuple.s_port),ntohs(tuple.d_port),s_mask,d_mask};
}
'''
suffix = r'''
static int set_aggregation(char *text) {
 mutex_lock(&aggr_config_lock);
 int ret=add_aggregation(text);
 mutex_unlock(&aggr_config_lock);
 return ret;
}
static int sysctl_write(char *text) {
 struct ctl_table ctl={aggregation_buf,sizeof(aggregation_buf)};
 size_t len=strlen(text);loff_t pos=0;
 return aggregation_procctl(&ctl,1,text,&len,&pos);
}
static void check_readback(const char *expected) {
 struct ctl_table ctl={aggregation_buf,sizeof(aggregation_buf)};
 char buf[1024]={0};size_t len=sizeof(buf)-1;loff_t pos=0;
 assert(!aggregation_procctl(&ctl,0,buf,&len,&pos));
 assert(!strcmp(buf,expected));
}
static atomic_int stop,observations;
static void check_snapshot(struct result r) {
 assert(r.smask==8 && r.dmask==8);
 assert((r.src==0x0a010000 && r.dst==0x0a020000 && r.sport==80 && r.dport==80) ||
        (r.src==0x0a000000 && r.dst==0x0a000000 && r.sport==443 && r.dport==443));
}
static void *reader(void *unused) {
 while(!stop) {check_snapshot(apply(AF_INET,IPPROTO_TCP));observations++;}
 return NULL;
}
static void *replacement(void *unused) {
 char input[]="10.0.0.0/8=8,80-89=443,3128=443";
 assert(!set_aggregation(input));
 return NULL;
}
int main(void) {
 char good[]="10.0.0.0/8=16,80-89=80,3128=80,";
 assert(set_aggregation(good)==0 && live==4);
 struct aggregation_rules *initial=rcu_dereference(aggr_ruleset);
 struct netflow_aggr_p *last=list_entry(initial->ports.prev,struct netflow_aggr_p,list);
 assert(last->port1==3128 && last->port2==3128 && last->aggr_port==80);
 const char *bad[]={"10.0.0.0/33=8","10.0.0.0/8=33","65536=80","1=65536","90-80=80","bad"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
  char input[100];strcpy(input,bad[i]);assert(set_aggregation(input)==-EINVAL && live==4);
  assert(rcu_dereference(aggr_ruleset)==initial);
 }
 for(int failure=1;failure<=4;failure++) {
  attempt=0;fail_at=failure;
  assert(set_aggregation(good)==-ENOMEM && live==4);
  assert(rcu_dereference(aggr_ruleset)==initial);
 }
 fail_at=0;
 strcpy(aggregation_buf,good);
 char invalid[]="10.0.0.0/33=8";
 assert(sysctl_write(invalid)==-EINVAL);
 check_readback(good);assert(rcu_dereference(aggr_ruleset)==initial && live==4);
 /* Fail the scratch buffer, container and each rule allocation separately. */
 for(int failure=1;failure<=5;failure++) {
  attempt=0;fail_at=failure;
  assert(sysctl_write(good)==-ENOMEM);
  check_readback(good);assert(rcu_dereference(aggr_ruleset)==initial && live==4);
 }
 fail_at=0;string_error=-EFAULT;
 assert(sysctl_write(good)==-EFAULT && live==4);
 string_error=0;check_readback(good);
 char partial_bad[]="1.0.0.0/8=16,80=70000";
 assert(set_aggregation(partial_bad)==-EINVAL && live==4);
 check_snapshot(apply(AF_INET,IPPROTO_TCP));
 struct netflow_aggr_n *net=list_entry(initial->nets.next,struct netflow_aggr_n,list);
 assert(net->usage==2);
 struct result r=apply(AF_INET6,IPPROTO_UDP);
 assert(r.src==0x0a010203 && !r.smask && r.sport==80 && r.dport==80);
 r=apply(AF_INET,IPPROTO_ICMP);
 assert(r.src==0x0a010000 && r.smask==8 && r.sport==81 && r.dport==3128);
 /* The replacement must publish both new lists before waiting, while leaving
  * the complete old snapshot intact for a reader already holding it. */
 pthread_t writer;
 rcu_read_lock();
 assert(!pthread_create(&writer,NULL,replacement,NULL));
 while(rcu_dereference(aggr_ruleset)==initial) sched_yield();
 assert(live==8 && net->aggr_mask==bits2mask(16));
 assert(initial->ports.prev==&last->list && last->aggr_port==80);
 rcu_read_unlock();
 assert(!pthread_join(writer,NULL));
 assert(live==4);
 pthread_t threads[4];
 for(int i=0;i<4;i++) assert(!pthread_create(&threads[i],NULL,reader,NULL));
 for(int i=0;i<200;i++) {
  if(i%2) replacement(NULL);else assert(!set_aggregation(good));
 }
 stop=1;
 for(int i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
 assert(observations>0 && live==4);
 char empty[]="";
 assert(sysctl_write(empty)==0 && live==1);check_readback(empty);
 r=apply(AF_INET,IPPROTO_TCP);
 assert(r.src==0x0a010203 && r.sport==81 && r.dport==3128);
 mutex_lock(&aggr_config_lock);aggregation_replace(NULL);mutex_unlock(&aggr_config_lock);
 assert(!rcu_dereference(aggr_ruleset) && live==0);
 r=apply(AF_INET,IPPROTO_TCP);
 assert(r.src==0x0a010203 && r.sport==81);
 puts("aggregation validation, rollback, packet semantics and concurrent RCU replacement checks passed");
}
'''
(out / 'aggregation.c').write_text(prefix + body + handler + apply + packet + apply_end + suffix)
subprocess.run(['gcc', '-g', '-O1', '-pthread', '-fsanitize=address,undefined',
                str(out / 'aggregation.c'), '-o', str(out / 'aggregation')], check=True)
subprocess.run([str(out / 'aggregation')], check=True, timeout=60,
               env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
