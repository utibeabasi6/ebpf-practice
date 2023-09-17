from bcc import BPF
import time

program = """
BPF_HASH(counter_table);

int counter(void *ctx){
    u64 *count;
    u64 pid;
    u64 curr_count = 0;

    pid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    count = counter_table.lookup(&pid);
    if (count != 0){
        curr_count = *count;
    }
    curr_count++;
    counter_table.update(&pid, &curr_count);
    return 0;
    
}
"""

bpf = BPF(text=program)

syscall = bpf.get_syscall_fnname("execve")

bpf.attach_kprobe(event=syscall, fn_name="counter")

while True:
    for k, v in bpf["counter_table"].items():
        print(f"Process with id {k.value}, has called execve {v.value} times")
    time.sleep(2)
    