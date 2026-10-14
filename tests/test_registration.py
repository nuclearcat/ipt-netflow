#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual NAT registration helpers with mock kernel lifetimes."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'ipt_NETFLOW.c').read_text()
start = source.index('static DEFINE_MUTEX(events_lock);')
end = source.index('\n#endif /* CONFIG_NF_NAT_NEEDED */', start)
helpers = source[start:end]
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>
#define DEFINE_MUTEX(n) pthread_mutex_t n=PTHREAD_MUTEX_INITIALIZER
#define mutex_lock pthread_mutex_lock
#define mutex_unlock pthread_mutex_unlock
#define printk(...) ((void)0)
#define KERN_INFO ""
#define KERN_ERR ""
#define rcu_assign_pointer(p,v) ((p)=(v))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct kset {int unused;};
struct kobject {struct kset *kset;};
struct module;
struct module_kobject {struct kobject kobj;struct module *mod;};
struct module {struct module_kobject mkobj;};
static struct kset modules;
static struct module self={.mkobj={.kobj={.kset=&modules}}}, owner;
#define THIS_MODULE (&self)
static int natevents, requests, pins, krefs, registrations, removals, active;
static int request_error, missing, cannot_pin, register_error;
static void *saved_event_cb;
static int natevents_net_ops;
static int request_module(const char *name) {requests++;return request_error;}
static struct kobject *kset_find_obj(struct kset *set,const char *name) {
 assert(set==&modules);if(missing)return NULL;krefs++;owner.mkobj.mod=&owner;return &owner.mkobj.kobj;
}
static int try_module_get(struct module *mod) {
 assert(mod==&owner && krefs==1);if(cannot_pin)return 0;pins++;return 1;
}
static void kobject_put(struct kobject *obj) {assert(krefs==1);krefs--;}
static void module_put(struct module *mod) {if(mod){assert(pins==1);pins--;}}
static int register_pernet_subsys(void *ops) {
 assert(!active);if(register_error)return register_error;active=1;registrations++;return 0;
}
static void unregister_pernet_subsys(void *ops) {assert(active);active=0;removals++;}
'''
suffix = r'''
static void *enable(void *unused) {assert(register_ct_events()==0);return NULL;}
static void *disable(void *unused) {unregister_ct_events();return NULL;}
int main(void) {
#if defined(CONFIG_NF_CT_NETLINK_MODULE) && !defined(CONFIG_SYSFS)
 assert(register_ct_events()==-EOPNOTSUPP);
 assert(!natevents && !pins && !active && !krefs);
#else
#ifdef CONFIG_NF_CT_NETLINK_MODULE
 request_error=-ENOENT;assert(register_ct_events()==-ENOENT);request_error=0;
 missing=1;assert(register_ct_events()==-ENODEV);missing=0;
 cannot_pin=1;assert(register_ct_events()==-ENODEV);cannot_pin=0;
 assert(!natevents && !pins && !krefs);
#endif
 register_error=-ENOMEM;assert(register_ct_events()==-ENOMEM);register_error=0;
 assert(!natevents && !pins && !active && !krefs);
 pthread_t threads[32];
 for(int i=0;i<32;i++)assert(!pthread_create(&threads[i],NULL,enable,NULL));
 for(int i=0;i<32;i++)pthread_join(threads[i],NULL);
 assert(natevents && active && registrations==1 && !krefs);
#ifdef CONFIG_NF_CT_NETLINK_MODULE
 assert(pins==1);
#else
 assert(pins==0);
#endif
 for(int i=0;i<32;i++)assert(!pthread_create(&threads[i],NULL,disable,NULL));
 for(int i=0;i<32;i++)pthread_join(threads[i],NULL);
 assert(!natevents && !active && !pins && !krefs && removals==1);
#endif
 puts("NAT registration lifetime and state checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    work = Path(tmp)
    (work / 'registration.c').write_text(prefix + helpers + suffix)
    for flags in ([], ['-DCONFIG_NF_CT_NETLINK_MODULE'],
                  ['-DCONFIG_NF_CT_NETLINK_MODULE', '-DCONFIG_SYSFS']):
        subprocess.run(['gcc', '-g', '-O1', '-pthread',
                        '-fsanitize=address,undefined', *flags,
                        str(work / 'registration.c'), '-o', str(work / 'test')], check=True)
        subprocess.run([str(work / 'test')], check=True,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
