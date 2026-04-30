

struct proc_info_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[TASK_COMM_LEN];
};

struct data_t {
    u32 pid;
    u32 uid;
    char pname[DNAME_INLINE_LEN];
    char fname[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
    char otype[TASK_COMM_LEN];
    int  is_killed;
    u32  process_inode;
};

BPF_PERF_OUTPUT(events);

BPF_HASH(sensitive_inodes, u64, u64);
BPF_HASH(authorized_exec_inodes, u64, u64);
BPF_HASH(proc_info_map, u32, struct proc_info_t);

// safe reader macro
#define READ_KERN(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), src)

static __always_inline void fill_op(char dst[TASK_COMM_LEN], int op)
{
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) dst[i] = 0;

    if (op == 1) { __builtin_memcpy(dst, "READ", 4); }
    if (op == 2) { __builtin_memcpy(dst, "KREAD", 5); }
    if (op == 3) { __builtin_memcpy(dst, "WRITE", 5); }
    if (op == 4) { __builtin_memcpy(dst, "KWRITE", 6); }
    if (op == 5) { __builtin_memcpy(dst, "RENAME", 6); }
    if (op == 6) { __builtin_memcpy(dst, "CREATE", 6); }
    if (op == 7) { __builtin_memcpy(dst, "DELETE", 6); }
    if (op == 8) { __builtin_memcpy(dst, "OPEN", 4); }
}

static __always_inline int safe_get_filename(struct dentry *de, char out[DNAME_INLINE_LEN])
{
    struct qstr dname = {};
    READ_KERN(dname, &de->d_name);

    // long name case
    if (dname.len > DNAME_INLINE_LEN - 1) {
        const char *p = NULL;
        READ_KERN(p, &dname.name);
        if (p) bpf_probe_read_kernel(out, DNAME_INLINE_LEN - 1, p);
        return 0;
    }

    // short (inline) name
    bpf_probe_read_kernel(out, dname.len, de->d_iname);
    return 0;
}

static __always_inline int handle_file(struct pt_regs *ctx,
                                       struct file *file,
                                       int op,
                                       bool is_read)
{
    if (!file)
        return 0;

    struct data_t data = {};

    // ---- read dentry safely ----
    struct dentry *de = NULL;
    READ_KERN(de, &file->f_path.dentry);
    if (!de)
        return 0;

    // ---- read inode safely ----
    struct inode *inode = NULL;
    READ_KERN(inode, &de->d_inode);
    if (!inode)
        return 0;

    u64 ino = 0;
    READ_KERN(ino, &inode->i_ino);

    // ---- read filename safely (needed before sensitive check) ----
    safe_get_filename(de, data.fname);

    // ---- detect /proc/<pid>/mem write (runtime .text tampering vector) ----
    bool is_proc_mem_write = false;
    if (!is_read &&
        data.fname[0] == 'm' && data.fname[1] == 'e' &&
        data.fname[2] == 'm' && data.fname[3] == 0) {
        is_proc_mem_write = true;
    }

    // ---- check sensitive list ----
    u64 *is_sens = sensitive_inodes.lookup(&ino);
    if (!is_sens && !is_proc_mem_write)
        return 0;

    // ---- Get process executable info ----
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *exe_file = NULL;
    struct mm_struct *mm = NULL;
    
    READ_KERN(mm, &task->mm);
    if (mm) {
        READ_KERN(exe_file, &mm->exe_file);
    }

    u32 process_inode = 0;
    char pname[DNAME_INLINE_LEN] = {};
    
    if (exe_file) {
        struct dentry *process_dentry = NULL;
        READ_KERN(process_dentry, &exe_file->f_path.dentry);
        
        if (process_dentry) {
            struct inode *proc_inode = NULL;
            READ_KERN(proc_inode, &process_dentry->d_inode);
            if (proc_inode) {
                READ_KERN(process_inode, &proc_inode->i_ino);
            }
            safe_get_filename(process_dentry, pname);
        }
    }

    // ---- SELF-PROTECTION: Block writes to authorized process binaries ----
    u64 *is_auth_exec = authorized_exec_inodes.lookup(&ino);
    if (is_auth_exec && !is_read) {
        // Someone is trying to modify an authorized executable
        // This is suspicious - block it silently
        return 0;
    }

    // ---- process info ----
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.process_inode = process_inode;
    
    #pragma unroll
    for (int i = 0; i < DNAME_INLINE_LEN; i++) {
        data.pname[i] = pname[i];
    }

    int unauthorized = 1;  // Default: unauthorized
    
    // First check: Is process executable in authorized list?
    if (process_inode != 0) {
        u64 proc_ino_64 = (u64)process_inode;
        u64 *is_authorized = authorized_exec_inodes.lookup(&proc_ino_64);
        if (is_authorized) {
            unauthorized = 0;  // Authorized by inode
        }
    }
    
    // Fallback check: Is comm name "scaphandre"?
    // This provides backward compatibility but is weaker
    if (unauthorized) {
        const char allowed[] = "scaphandre";
        int match = 1;
        
        #pragma unroll
        for (int i = 0; i < (int)(sizeof(allowed) - 1); i++) {
            if (data.comm[i] != allowed[i]) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            unauthorized = 0;  // Authorized by comm name
        }
    }

    // ---- op name ----
    fill_op(data.otype, op);

    // Rust side interprets this as "unauthorized"
    data.is_killed = unauthorized;

    // ---- emit ----
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// vfs_read
int trace_read(struct pt_regs *ctx, struct file *file,
               char __user *buf, size_t count)
{
    return handle_file(ctx, file, 1, true);
}

// kernel_read
int trace_kernel_read(struct pt_regs *ctx, struct file *file,
                      char __user *buf, size_t count)
{
    return handle_file(ctx, file, 2, true);
}

// vfs_write
int trace_write(struct pt_regs *ctx, struct file *file,
                const char __user *buf, size_t count)
{
    return handle_file(ctx, file, 3, false);
}

// kernel_write
int trace_kernel_write(struct pt_regs *ctx, struct file *file,
                       const char __user *buf, size_t count)
{
    return handle_file(ctx, file, 4, false);
}

// vfs_rename - file rename operations
int trace_rename(struct pt_regs *ctx, struct inode *old_dir,
                 struct dentry *old_dentry, struct inode *new_dir,
                 struct dentry *new_dentry)
{
    struct dentry *de = NULL;
    READ_KERN(de, &old_dentry);
    if (!de)
        return 0;

    struct inode *inode = NULL;
    READ_KERN(inode, &de->d_inode);
    if (!inode)
        return 0;

    u64 ino = 0;
    READ_KERN(ino, &inode->i_ino);
    
    u64 *is_sens = sensitive_inodes.lookup(&ino);
    if (!is_sens)
        return 0;

    struct data_t data = {};
    safe_get_filename(de, data.fname);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    fill_op(data.otype, 5);
    data.is_killed = 1;  // Renaming sensitive files is unauthorized
    data.process_inode = 0;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// security_inode_create - file creation
int trace_create(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    if (!dentry || dentry->d_name.len == 0)
        return 0;

    struct data_t data = {};
    safe_get_filename(dentry, data.fname);
    
    // Check if creating a file with sensitive name pattern
    const char sens_name[] = "energy_uj";
    int match = 1;
    
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(sens_name) - 1); i++) {
        if (i >= DNAME_INLINE_LEN || data.fname[i] != sens_name[i]) {
            match = 0;
            break;
        }
    }
    
    if (!match)
        return 0;
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    fill_op(data.otype, 6);
    data.is_killed = 1;  // Creating energy_uj files is suspicious
    data.process_inode = 0;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// vfs_unlink - file deletion
int trace_delete(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry)
{
    struct dentry *de = NULL;
    READ_KERN(de, &dentry);
    if (!de)
        return 0;

    struct inode *inode = NULL;
    READ_KERN(inode, &de->d_inode);
    if (!inode)
        return 0;

    u64 ino = 0;
    READ_KERN(ino, &inode->i_ino);
    
    u64 *is_sens = sensitive_inodes.lookup(&ino);
    if (!is_sens)
        return 0;

    struct data_t data = {};
    safe_get_filename(de, data.fname);
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    fill_op(data.otype, 7);
    data.is_killed = 1;  // Deleting sensitive files is unauthorized
    data.process_inode = 0;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Process execution tracking
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct proc_info_t info = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 ppid = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    READ_KERN(parent, &task->real_parent);
    
    if (parent) {
        READ_KERN(ppid, &parent->pid);
    }

    info.pid = pid;
    info.ppid = ppid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    bpf_get_current_comm(&info.filename, sizeof(info.filename));

    proc_info_map.update(&info.pid, &info);
    return 0;
}

// Monitor perf_event_open syscalls (potential monitoring bypass attempts)
TRACEPOINT_PROBE(syscalls, sys_enter_perf_event_open)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_trace_printk("[EBPF-GUARD] pid=%d attempting perf_event_open\\n", pid);
    return 0;
}

