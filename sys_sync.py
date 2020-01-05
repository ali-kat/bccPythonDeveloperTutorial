from bcc import BPF
b = BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("sys_sync() called!\\n"); return 0; }')

while 1:
	print("Tracing sys_sync()... Ctrl-C to end!")
	try:
		b.trace_print()
	except KeyboardInterrupt:
		print("Good bye!")
		exit()