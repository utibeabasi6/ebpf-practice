from bcc import BPF

program = """
int hello(void *ctx){
    bpf_trace_printk("hello world");
    return 0;
}
"""


bpf = BPF(text=program)

syscall = bpf.get_syscall_fnname("execve")

bpf.attach_kprobe(event=syscall, fn_name="hello")

bpf.trace_print()