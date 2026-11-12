#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check serialized sysctl text access and parser error propagation."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'ipt_NETFLOW.c').read_text()
def function(name):
    return re.search(r'^static int ' + name + r'\([^;]*?\n\{.*?^\}', source, re.M | re.S).group()
code = r'''
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define PROC_CTL_TABLE struct ctl_table
#define BEFORE2632(a,b)
#define __user
#define KERN_INFO ""
#define KERN_WARNING ""
#define printk(...) ((void)0)
struct ctl_table {void *data;};
typedef struct ctl_table ctl_table_no_const;
static pthread_mutex_t string_config_lock=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local int locked;
#define mutex_lock(p) do {pthread_mutex_lock(p);assert(!locked++);}while(0)
#define mutex_unlock(p) do {assert(locked--==1);pthread_mutex_unlock(p);}while(0)
static char destination_buf[256]="old",sampler_buf[128]="old",snmp_rules_buf[256]="old";
static int debug,ts_sampler_last,flows_observed,flows_selected;
static struct ipt_netflow_stat {int pkts_selected,pkts_observed;} stats;
#define per_cpu(s,c) stats
#define for_each_present_cpu(c) for(c=0;c<1;c++)
#define atomic64_set(p,v) (*(p)=(v))
#define AND_FLUSH 1
static int paused;
static void pause_scan_worker(void) {assert(locked);assert(!paused++);}
static void cont_scan_worker(void) {assert(paused--==1);}
static void destination_removeall(void) {assert(locked && paused);}
static void free_templates(void) {assert(locked && paused);}
static void netflow_scan_and_export(int f) {assert(locked && paused);}
static int parse(const char *s) {assert(locked);return !strcmp(s,"bad")?-EINVAL:!strcmp(s,"oom")?-ENOMEM:0;}
static int add_destinations(const char *s) {return parse(s);}
static int add_snmp_rules(char *s) {return parse(s);}
static int parse_sampler(char *s) {int r=parse(s);strcpy(sampler_buf,r?"":s);return r;}
static int proc_dostring(struct ctl_table *ctl,int write,void *buffer,size_t *len,loff_t *pos) {
 assert(locked);
 if(write)memcpy(ctl->data,buffer,*len+1);
 else {size_t n=strlen(ctl->data);memcpy(buffer,ctl->data,n+1);*len=n;}
 return 0;
}
'''
code += '\n'.join(function(n) for n in ('destination_procctl', 'sampler_procctl', 'snmp_procctl'))
code += r'''
typedef int (*handler)(struct ctl_table *,int,void *,size_t *,loff_t *);
static handler handlers[]={destination_procctl,sampler_procctl,snmp_procctl};
static void *exercise(void *arg) {
 struct ctl_table ctl={0};
 for(int n=0;n<1000;n++)for(unsigned i=0;i<3;i++) {
  char text[256]="valid";size_t len=5;loff_t pos=0;
  assert(!handlers[i](&ctl,1,text,&len,&pos));
  len=sizeof(text);assert(!handlers[i](&ctl,0,text,&len,&pos));assert(!strcmp(text,"valid"));
 }
 return NULL;
}
int main(void) {
 struct ctl_table ctl={0};char *buffers[]={destination_buf,sampler_buf,snmp_rules_buf};
 for(unsigned i=0;i<3;i++)for(int e=0;e<2;e++) {
  char *s=e?"oom":"bad";size_t len=3;loff_t pos=0;
  assert(handlers[i](&ctl,1,s,&len,&pos)==(e?-ENOMEM:-EINVAL));
  assert(!strcmp(buffers[i],i==1?"":"old"));
 }
 pthread_t threads[4];
 for(int i=0;i<4;i++)assert(!pthread_create(&threads[i],NULL,exercise,NULL));
 for(int i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
 puts("sysctl text locking and error checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'sysctl.c').write_text(code)
    subprocess.run(['gcc', '-pthread', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'sysctl.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
