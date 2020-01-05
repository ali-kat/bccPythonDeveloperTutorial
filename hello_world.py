from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()

#text='...' defines a BPF program inline
#kprobe__sys_clone() is a shortcut for kernel dynamic tracing via kprobes, if the C function begins with kprobe__, the rest is treated as a kernel function name to instrument
#what do they mean when they say 'the rest is treated as a kernel function name to instrument'
#void *ctx, ctx has arguments, but since we are not using them here, we cast them to void *
#what is ctx?
#return 0 is a necessary formality (https://github.com/iovisor/bcc/issues/139)
#.trace_print() is a bcc reoutine that reaads trace_pipe and prints the output