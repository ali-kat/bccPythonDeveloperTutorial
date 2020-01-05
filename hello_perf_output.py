#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>
//https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h
//this is for TASK_COMM_LEN

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        b"Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

#stop using bpf_trace_printk() and use the proper BPF_PERF_OUTPUT() interface 
#we will stop getting the free trace_field() members like PID and timestamp, we will have to fetch them directly
#struct data_t, defines the C struct we will use to pass data from the kernel to the userspace 
#BPF_PERF_OUTPUT(events), name our output channel "events"
#struct data_t data = {}, create an empty data_t struct that we will then populate 
#bpf_get_current_pid_tgid(), returns the process ID in the lower 32 bits (kernel's view of the PID, userspace's thread ID) and the thread group ID in the upper 32 bits (userspace's PID), by directly setting this to u32 we discard the upper 32 bits 
#should you present the PID or the TGID?
#bpf_get_current_comm(&data.comm, sizeof(data.comm)), populates the first argument address with the current process name 
#events.perf_submit(ctx, &data, sizeof(data)), submit the event for the user space to read via a perf ring buffer 
#def print_event(cpu, data, size), define a python function that will handle reading events from the events stream 
#b["events"].event(data), now get the event as a Python object, auto-generated from the C declaration 
#b["events"].open_perf_buffer(print_event), associate the python print_event function with the events stream 
#while 1: try: b.perf_buffer_poll(), block waiting for events 