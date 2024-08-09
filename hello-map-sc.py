'''
The program shows the total number of syscall for each user ID by attaching the program to the sys_enter (tracepoint).
'''

#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table); // counter => uid
BPF_PROG_ARRAY(syscall, 300); // syscall => opcode 

int hello_syscall(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_count(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}
"""
b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello_count")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
    #print("\n")


'''
Output
(base) alex:~/cods/ebpf/chapter2/Exercises/3$ sudo ./hello-map-sc.py 
ID 0: 206   ID 1000: 2220  ID 108: 273 
ID 104: 12  ID 0: 554   ID 1000: 6905  ID 108: 505 
ID 104: 12  ID 0: 846   ID 1000: 10270 ID 108: 778 
ID 104: 12  ID 0: 1078  ID 1000: 18549 ID 116: 4   ID 108: 1052   
ID 104: 12  ID 0: 1293  ID 1000: 22844 ID 116: 4   ID 108: 1325   
ID 104: 24  ID 113: 2   ID 102: 14  ID 101: 53  ID 0: 1909  ID 1000: 27692 ID 116: 4   ID 108: 1570   
ID 104: 31  ID 113: 4   ID 102: 14  ID 101: 53  ID 0: 2198  ID 1000: 30125 ID 116: 8   ID 108: 1844   
'''
    
