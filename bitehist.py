#!/usr/bin/python
#
# bitehist.py	Block I/O size histogram.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of using histograms to show a distribution.
#
# A Ctrl-C will print the gathered histogram then exit.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Aug-2015	Brendan Gregg	Created this.
# 03-Feb-2019   Xiaozhou Liu    added linear histogram.

from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist_linear);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	dist.increment(bpf_log2l(req->__data_len / 1024));
	dist_linear.increment(req->__data_len / 1024);
	return 0;
}
""")

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
print("log2 histogram")
print("~~~~~~~~~~~~~~")
b["dist"].print_log2_hist("kbytes")

print("\nlinear histogram")
print("~~~~~~~~~~~~~~~~")
b["dist_linear"].print_linear_hist("kbytes")

#recap 
#kprobe__, this prefix means that the rest will be treated as a kernel function that will be instrumented using kprobe
#struct pt_regs *ctx, struct request *req, are arguments to kprobe, the ctx is registers and the BPF context, the req is the first argument to the instrumented function (blk_account_io_completion())
#req->__data_len, dereferencing that member

#new info 
#BPF_HISTOGRAM(dist), defines a BPF map object that is a histogram, and names it "dist"
#dist.increment(bpf_log2l(req->__data_len / 1024)), increments the histogram bucket index provided as first argument by one by default, optionally custom increments can be passed as the second argument 
#bpf_log2l(req->__data_len / 1024), returns the log-2 of the provided value, this becomes the index of our histogram, so we are constructing a power-of-2 histogram 
#b["dist"].print_log2_hist("kbytes"), prints the "dist" histogram as power-of-2 with a column header of "kbytes"
#the only data transferred from kernel to userspace is the bucket counts, making this efficient 