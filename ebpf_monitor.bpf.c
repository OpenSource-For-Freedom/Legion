// active monitoring 
SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx) {
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[0]);
    bpf_printk("Process executed: %s", filename);
    return 0;
}

char _license[] SEC("license") = "GPL";
