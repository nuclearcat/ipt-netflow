#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

root=Path(__file__).resolve().parents[1]
workspace = tempfile.TemporaryDirectory(prefix='ipt-netflow-test-')
out=Path(workspace.name)
baseline='--baseline' in sys.argv
src=subprocess.check_output(['git','show','f6133dd:snmp_NETFLOW.c'],cwd=root,text=True) if baseline else (root/'snmp_NETFLOW.c').read_text()
prefix=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
static char input[100000];
static size_t input_size;
static FILE *test_fopen(const char *path,const char *mode) { return fmemopen(input,input_size,"r"); }
static int test_open(const char *path,int flags,...) { return 42; }
static ssize_t test_read(int fd,void *buf,size_t len) { if(len>input_size) len=input_size; memcpy(buf,input,len); return len; }
static int test_close(int fd) { return 0; }
#define fopen test_fopen
#define open test_open
#define read test_read
#define close test_close
'''
suffix=r'''
#undef fopen
#undef open
#undef read
#undef close
int main(int argc,char **argv) {
 cpu_data_set=netsnmp_create_table_data_set("testcpu");
 sock_data_set=netsnmp_create_table_data_set("testsock");
 if(!strcmp(argv[1],"unsupported")) {
  struct snmp_vars bad[]={{1,ASN_INTEGER,"index"},{2,ASN_NULL,"bad"},{3,ASN_INTEGER,"next"},{0}};
  char row[]="7 8";
  parse_table_row(0,row,bad,cpu_data_set);
  assert(!netsnmp_table_data_get_first_row(cpu_data_set->table));
 } else {
  if(!strcmp(argv[1],"large")) {
   input_size=sprintf(input,"inPackets 123\n");
   for(int cpu=0;cpu<256;cpu++)
    input_size+=sprintf(input+input_size,"cpu%d 1 2 3 4 1.00 6 7 8 9 10 11\n",cpu);
   input_size+=sprintf(input+input_size,"sock0 127.0.0.1:2055 1 0 0 0 0 4096 0 0\nsndbufPeak 4096\n");
   assert(input_size>4095);
  } else if(!strcmp(argv[1],"longline")) {
   input_size=sprintf(input,"unknown ");
   memset(input+input_size,'7',6000); input_size+=6000;
   input_size+=sprintf(input+input_size,"\ninPackets 123\nsndbufPeak 4096");
  } else {
   input_size=sprintf(input,"malformed\ninPackets 123\nsndbufPeak 4096");
  }
  grab_ipt_netflow_snmp(1000);
  assert(find_varinfo_str(totals,"inPackets")->val64==123);
  assert(find_varinfo_str(totals,"sndbufPeak")->val64==4096);
  if(!strcmp(argv[1],"large")) {
   int rows=0;
   for(netsnmp_table_row *r=netsnmp_table_data_get_first_row(cpu_data_set->table);r;r=netsnmp_table_data_get_next_row(cpu_data_set->table,r)) rows++;
   assert(rows==256);
   assert(netsnmp_table_data_get_first_row(sock_data_set->table));
  }
 }
 clear_data_set(cpu_data_set); clear_data_set(sock_data_set);
 puts("SNMP checks passed");
 return 0;
}
'''
name='snmp-baseline' if baseline else 'snmp-fixed'
(out/(name+'.c')).write_text(prefix+src+suffix)
subprocess.run(['gcc','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-I',os.environ.get('NET_SNMP_INCLUDE','/usr/include'),str(out/(name+'.c')),'-o',str(out/name),*shlex.split(os.environ.get('NET_SNMP_LIBS','-lnetsnmpagent -lnetsnmp'))],check=True)
env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0')
for case in (['large','longline','unterminated'] if '--row' not in sys.argv else ['unsupported']):
 r=subprocess.run([str(out/name),case],env=env,capture_output=True,text=True)
 print(case,'PASS' if r.returncode==0 else 'FAIL',r.stdout,r.stderr[:1600])
 if r.returncode and not baseline: sys.exit(1)
