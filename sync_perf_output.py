#rewrite sync_timing.py to use BPF_PERF_OUTPUT

from __future__ import print_function 
from bcc import BPF 

#load BPF program
b = BPF(text="""
#include <linux/sched.h>
//https://elixir.bootlin.com/linux/latest/source/include/linux/sched.h
//this is for TASK_COMM_LEN

// define output data structure in C
struct data_t {
    u64 ts;
    u64 delta; 
};

BPF_PERF_OUTPUT(events);
BPF_HASH(last); 

int do_trace(struct pt_regs *ctx){
  struct data_t data = {};
  u64 ts, *tsp, delta, key = 0;

  // attempt to read stored timestamp 
  tsp = last.lookup(&key);
  if(tsp != 0){
    delta = bpf_ktime_get_ns() - *tsp;
    if(delta < 1000000000){
        //output if time is less than 1 second 
        data.delta = delta / 1000000; // used to be ms
        //has to be here or else it will print for one sync!
        data.ts = bpf_ktime_get_ns(); 
        events.perf_submit(ctx, &data, sizeof(data));
    }
    last.delete(&key);
  }

  //update stored timestamp 
  ts = bpf_ktime_get_ns();  
  last.update(&key, &ts); 
  return 0;  
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end!")

start = 0 
def print_event(cpu, data, size):
    global start
    events = b["events"].event(data)
    if start == 0:
    	start = events.ts
    #why is this division necessary with perf_output? 
    ts = (float(events.ts - start)) / 1000000000
    print("At time %.2f s: multiple syncs detected, last %6d ms ago" % (ts, events.delta)); 

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)    
while 1:
    try:
    	b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Good bye!")
        exit()
