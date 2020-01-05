from bcc import BPF

# define BPF program
prog = """
int hello(void *ctx) {
	bpf_trace_printk("Hello, World!\\n");
	return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
	except ValueError:
		continue
	print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

#prog= this time we declare the C program as a variable, and later refer to it, this is useful if you want to add some string substitutions based on CLI arguments
#hello(), we are declaring a C function instead of the kprobe__ shortcut
#all C functions declared in the BPF program are expected to be executed on a probe, hence they all need to take a pt_reg* ctx as first argument 
#if you need to define some helper function that will not be executed on a probe, they need to be defined as static inline, in order to be inlined by the compiler 
#sometimes you also need to add _always_inline function attribute to it 
#b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello"), creates a kprobe for the kernel clone system call function, which will execute our defined hello() function 
#you can call the attach_kprobe() more than once, and attach your C function to multiple kernel functions
#b.trace_fields(), returns aa fixed set of fields from trace_pipe, similar to trace_print() 
#handy for hacking, but we should use BPF_PERF_OUTPUT()