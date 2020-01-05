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

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb 

REQ_WRITE = 1		# from include/linux/blk_types.h
#https://elixir.bootlin.com/linux/latest/source/include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
//https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ptrace.h
#include <linux/blkdev.h>
//https://elixir.bootlin.com/linux/latest/source/include/linux/blkdev.h
//https://elixir.bootlin.com/linux/latest/source/include/linux/blkdev.h#L132

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();

	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;

	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %x %d\\n", req->__data_len,
		    req->cmd_flags, delta / 1000);
		start.delete(&req);
	}
}
""")

if BPF.get_kprobe_functions(b'blk_start_request'):
	b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_completion")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
		(bytes_s, bflags_s, us_s) = msg.split()

		if int(bflags_s, 16) & REQ_WRITE:
			type_s = b"W"
		elif bytes_s == "0":	# see blk_fill_rwbs() for logic
			type_s = b"M"
		else:
			type_s = b"R"
		ms = float(int(us_s, 10)) / 1000

		printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
	except KeyboardInterrupt:
		exit()

#REQ_WRITE is a kernel constant in the Python program, we define it in the python program, because we will use it there later, if we were using REQ_WRITE in the BPF program it should also just work with the appropriate includes 
#void trace_start(struct pt_regs *ctx, struct request *req), this function will be later attached to kprobes, the arguments to the kprobe functions are struct pt_regs *ctx for registers and BPF context, and then actual arguments to the function, we will attach this to blk_start_request(), where the first argument is struct request *. 
#start.update(&req, &ts), we are using a pointer to the request struct as a key in our hash (pointers to structs turn out to be great keys, since they are unique, as two structs can't have the same pointer address)
#so we are tagging the request struct which describes disk I/O, with our own timestamp, so we can time it 
#req->__data_len, dereferencing members of struct request, bcc actually rewrites these expressions to be a series of bpf_probe_read() calls, sometimes you may need to call bpf_probe_read() directly as bcc can't handle a complex dereference 