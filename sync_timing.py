from __future__ import print_function 
from bcc import BPF 

#load BPF program
b = BPF(text="""

BPF_HASH(last); 

int do_trace(struct pt_regs *ctx){
  u64 ts, *tsp, delta, key = 0;

  // attempt to read stored timestamp 
  tsp = last.lookup(&key);
  if(tsp != 0){
    delta = bpf_ktime_get_ns() - *tsp;
    if(delta < 1000000000){
        //output if time is less than 1 second 
        bpf_trace_printk("%d\\n", delta / 1000000);
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

#format output
start = 0 
while 1:

    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    except KeyboardInterrupt:
        print("Good bye!")
        exit()

#bpf_ktime_get_ns() returns time aas nanoseconds 
#BPF_HASH(last); creates a BPF map object that is a hash (associative array) called "last", defaults to key and value types of u64, however it can be specified in further arguments 
#key = 0, we will only have one key/value pair, and the key will always be 0 
#last.lookup(&key), look up the key in the hash, and return a pointer to it's value (if it exists), otherwise NULL, we pass the key in as an address to a pointer 
#last.delete(&key), delete the key from the hash, due to a kernel bug this is required, link to relevant repo no longer works 
#last.update(&key, &ts), associate the value to the key, overwriting the previous value, records the timestamp 