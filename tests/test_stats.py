#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify worker counter updates exclude migration and softirq interruption."""
from pathlib import Path
import os
import subprocess
import tempfile

header = (Path(__file__).resolve().parents[1] / 'ipt_NETFLOW.h').read_text()
start = header.index('#define NETFLOW_STAT_INC(')
end = header.index('#define NETFLOW_STAT_READ(', start)
code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef uint64_t ktime_t;
static int bh_depth,checks;
static uint64_t clock_now;
struct duration {uint64_t first,last;};
struct stats {uint64_t packets,bytes;struct duration lost;} stats;
static struct stats *get_stats(void) {assert(bh_depth);checks++;return &stats;}
#define __get_cpu_var(x) (*get_stats())
#define first_tv64 first
#define local_bh_disable() (++bh_depth)
#define local_bh_enable() (--bh_depth)
#define ktime_get_real() (++clock_now)
'''
code += header[start:end] + r'''
int main(void) {
 NETFLOW_STAT_INC_ATOMIC(packets);assert(stats.packets==1 && !bh_depth);
 NETFLOW_STAT_ADD_ATOMIC(bytes,1ULL<<40);assert(stats.bytes==(1ULL<<40) && !bh_depth);
 NETFLOW_STAT_TS_ATOMIC(lost);assert(stats.lost.first==1 && stats.lost.last==1 && !bh_depth);
 NETFLOW_STAT_TS_ATOMIC(lost);assert(stats.lost.first==1 && stats.lost.last==2 && !bh_depth);
 bh_depth=1;NETFLOW_STAT_ADD_ATOMIC(packets,2);assert(stats.packets==3 && bh_depth==1);
 assert(checks>0);
 puts("per-CPU worker statistics checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='ipt-netflow-test-') as tmp:
    path = Path(tmp)
    (path / 'stats.c').write_text(code)
    subprocess.run(['gcc', '-g', '-O1', '-fsanitize=address,undefined',
                    str(path / 'stats.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=0'))
