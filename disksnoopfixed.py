#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

#modified to use block:block_rq_issue and block:block_rq_complete tracepoints
#please see urandomread.py

#difficulty making it work with the rwbs field, which i believe is required for the T field (R/W)
#don't feel like pulling my hair over this issue, so I may return to it later

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb 

REQ_WRITE = 1		# from include/linux/blk_types.h
#https://elixir.bootlin.com/linux/latest/source/include/linux/blk_types.h

# load BPF program
b = BPF(text="""
// no charer use struct request 
BPF_HASH(time, u64);
BPF_HASH(size, u64, int); 
TRACEPOINT_PROBE(block, block_rq_issue) {
	u64 pid, ts; 
	int bytes;

	pid = args->dev; 
    ts = bpf_ktime_get_ns();
    bytes = args->bytes; 

	time.update(&pid, &ts);
	size.update(&pid, &bytes);

    return 0;
}
//sudo cat /sys/kernel/debug/tracing/events/block/block_rq_issue/format

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 *tsp, delta, pid;
    int *bytes;

    pid = args->dev; 
	tsp = time.lookup(&pid);
	bytes = size.lookup(&pid);

	if (tsp != 0 && bytes != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %d\\n", *bytes, delta/1000);
	}
    return 0;
}
//sudo cat /sys/kernel/debug/tracing/events/block/block_rq_complete/format
""")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		(bytes_s, us_s) = msg.split()

		#if int(bflags_s, 16) & REQ_WRITE:
		#	type_s = b"W"
		#elif bytes_s == "0":	# see blk_fill_rwbs() for logic
		#	type_s = b"M"
		#else:
		#	type_s = b"R"
		
		ms = float(int(us_s, 10)) / 1000
		
		printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, b"  ", bytes_s, ms))
	except KeyboardInterrupt:
		exit()