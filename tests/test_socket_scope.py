#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check that source bind and connect receive the selected IPv6 interface zone."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / 'ipt_NETFLOW.c').read_text()
def function(name):
    return re.search(r'^static[^\n]*\b' + name + r'\([^;]*?\n\{.*?^\}', source, re.M | re.S).group()
code = r'''
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#define LINUX_VERSION_CODE 1
#define KERNEL_VERSION(a,b,c) 0
#define GFP_ATOMIC 0
#define SK_CAN_REUSE 1
#define KERN_ERR ""
#define printk(...) ((void)0)
#define SOCKADDR_CAST(p) ((struct sockaddr *)(p))
struct sock;
struct proto {void (*unhash)(struct sock *);void (*rehash)(struct sock *);};
struct sock {int sk_allocation,sk_reuse,sk_bound_dev_if,sk_sndbuf;struct proto *sk_prot;void *sk_user_data;void (*sk_error_report)(struct sock *);};
struct socket;
struct ops {int (*bind)(struct socket *,struct sockaddr *,int);int (*connect)(struct socket *,struct sockaddr *,int,int);};
struct socket {struct sock *sk;struct ops *ops;};
struct ipt_netflow_sock {struct sockaddr_storage addr,saddr;char sdev[IFNAMSIZ];};
struct net_device {int ifindex;};
static struct net_device device={.ifindex=7};
static int expected_scope,binds,connects,releases,sndbuf,init_net;
static int bind_socket(struct socket *s,struct sockaddr *a,int len) {
 if(a->sa_family==AF_INET6)assert(((struct sockaddr_in6 *)a)->sin6_scope_id==expected_scope);
 binds++;return 0;
}
static int connect_socket(struct socket *s,struct sockaddr *a,int len,int flags) {
 if(a->sa_family==AF_INET6)assert(((struct sockaddr_in6 *)a)->sin6_scope_id==expected_scope);
 connects++;return 0;
}
static void unhash(struct sock *s) {}
static void netflow_sk_error_report(struct sock *s) {}
static struct proto proto={.unhash=unhash};
static struct ops ops={bind_socket,connect_socket};
static struct sock sk;
static struct socket sock={&sk,&ops};
static int sock_create_kern(int family,int type,int protocol,struct socket **result) {
 memset(&sk,0,sizeof(sk));sk.sk_prot=&proto;*result=&sock;return 0;
}
static struct net_device *dev_get_by_name(void *net,const char *name) {return strcmp(name,"missing")?&device:NULL;}
#define dev_put(p) ((void)0)
#define sk_dst_reset(p) ((void)0)
#define sock_release(p) (releases++)
'''
code += function('is_zero_addr') + function('usock_open_sock') + r'''
int main(void) {
 struct ipt_netflow_sock s={0};
 struct sockaddr_in6 *dest=(void *)&s.addr,*src=(void *)&s.saddr;
 dest->sin6_family=src->sin6_family=AF_INET6;
 assert(inet_pton(AF_INET6,"fe80::1",&dest->sin6_addr)==1);
 assert(inet_pton(AF_INET6,"fe80::2",&src->sin6_addr)==1);
 strcpy(s.sdev,"eth0");expected_scope=7;
 assert(usock_open_sock(&s)==&sock && binds==1 && connects==1 && sk.sk_bound_dev_if==7);
 device.ifindex=expected_scope=9;
 assert(usock_open_sock(&s)==&sock && binds==2 && connects==2 && sk.sk_bound_dev_if==9);
 strcpy(s.sdev,"missing");assert(!usock_open_sock(&s));assert(releases==1 && connects==2);
 puts("IPv6 socket scope checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'scope.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'scope.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
