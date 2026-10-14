#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check exporter boundaries and arithmetic using the production C functions."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'ipt_NETFLOW.c').read_text()
header = (root / 'ipt_NETFLOW.h').read_text()

def function(name):
    return re.search(r'^static[^\n]*\b' + name + r'\([^;]*?\n\{.*?^\}',
                     source, re.S | re.M).group()

structs = '\n'.join(re.search(r'struct ' + name + r' \{.*?packed\)\);', header, re.S).group()
                    for name in ('netflow5_record', 'netflow5_pdu', 'netflow9_pdu',
                                 'ipfix_pdu', 'flowset_data'))
globals_start = source.index('static long long pdu_packets')
globals_end = source.index('\nstatic unsigned long wk_start', globals_start)
globals_code = source[globals_start:globals_end]
metric_start = source.index('#define RATESHIFT')
metric_end = source.index('// calculate EWMA', metric_start)
options_start = source.index('static inline __u32 ip4_options(')
options_end = source.index('/* check if data region', options_start)
spi = re.search(r'^#define EXTRACT_SPI.*$', header, re.M).group()
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tcp.h>
typedef uint64_t u64;
typedef int64_t s64;
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define div64_u64(a,b) ((a)/(b))
#define likely(x) (x)
#define unlikely(x) (x)
#define printk(...) ((void)0)
#define KERN_INFO ""
#define PAD_SIZE 4
#define NETFLOW5_RECORDS_MAX 30
#define NETFLOW5_HEADER_SIZE (sizeof(struct netflow5_pdu)-30*sizeof(struct netflow5_record))
static int debug;
static unsigned long jiffies=1000;
static unsigned engine_id=3;
#define jiffies_to_msecs(x) (x)
static void do_gettimeofday(struct timeval *tv) {tv->tv_sec=123;tv->tv_usec=987654;}
static unsigned char sent[2048];
static int sent_size;
static void netflow_sendmsg(void *data,int size) {assert(size<=sizeof(sent));memcpy(sent,data,size);sent_size=size;}
struct sk_buff {unsigned char data[64];unsigned len;};
static void *skb_header_pointer(const struct sk_buff *skb,unsigned off,unsigned len,void *buffer) {
 return off+len<=skb->len?(void *)(skb->data+off):NULL;
}
'''
main = r'''
int main(void) {
 for(int version=9;version<=10;version++) {
  size_t total=version==9?sizeof(pdu.v9):sizeof(pdu.ipfix);
  unsigned char *data=version==9?pdu.v9.data:pdu.ipfix.data;
  for(int gap=0;gap<8;gap++) {
   memset(&pdu,0xcc,sizeof(pdu));
   pdu_high_wm=(unsigned char *)&pdu+total-3;
   pdu_data_used=pdu_high_wm-gap;
   pdu_flowset=(void *)data;
   size_t length=pdu_data_used-data;
   unsigned padding=(4-length%4)%4;
   pdu_flowset->length=htons(length);
   pdu_flowset->flowset_id=htons(256);
   pdu_data_records=1;
   if(version==9)netflow_export_pdu_v9();else netflow_export_pdu_ipfix();
   struct flowset_data *fs=(void *)(sent+(data-(unsigned char *)&pdu));
   assert(ntohs(fs->length)==length+padding && ntohs(fs->length)%4==0);
   assert(sent_size==total-3-gap+padding && sent_size<=total);
   for(unsigned i=0;i<padding;i++)assert(sent[sent_size-padding+i]==0);
   if(version==10)assert(ntohs(((struct ipfix_pdu *)sent)->length)==sent_size);
  }
 }
 pdu_data_records=1;netflow_export_pdu_v5();
 assert(ntohl(((struct netflow5_pdu *)sent)->ts_unsecs)==987654000);
 assert(hash_metric(0,0,0,123)==123);
 assert(hash_metric(0,30000000,0,0)==100);
 assert(hash_metric(30000000,30000000,0,0)==200);
 assert(hash_metric(0,1ULL<<32,0,0)==100);
 assert(hash_metric(1000000000,1,0,0)==INT_MAX);
 int average=0;CALC_RATE(average,INT_MAX,1);assert(average>0);
 unsigned char ip_options[]={137,2,0};
 assert(ip4_options(ip_options,sizeof(ip_options))==((1U<<22)|(1U<<31)));
 for(unsigned option=0;option<32;option++) {
  unsigned char value=option;
  assert(ip4_options(&value,1)==(1U<<(31-option)));
 }
 struct sk_buff skb={.len=24};struct tcphdr th={.doff=6};
 assert(tcp_options(&skb,0,&th)==(1U<<31));
 struct {uint16_t s_port,d_port;} tuple={0xffff,0xffff};
 assert(EXTRACT_SPI(tuple)==0xffffffffU);
 puts("PDU padding, timestamps, metrics, options and SPI checks passed");
}
'''
code = (prefix + structs + globals_code + '\n' + spi + '\n' +
        function('pdu_have_space') + '\n' + function('pdu_grab_space') + '\n' +
        '\n'.join(function(name) for name in ('netflow_export_pdu_v5',
                                             'netflow_export_pdu_v9',
                                             'netflow_export_pdu_ipfix')) +
        '\n' + source[metric_start:metric_end] + source[options_start:options_end] + main)
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    work = Path(tmp)
    (work / 'exports.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(work / 'exports.c'), '-o', str(work / 'test')], check=True)
    subprocess.run([str(work / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
