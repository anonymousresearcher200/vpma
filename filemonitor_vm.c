

#define DNAME_INLINE_LEN 32

struct data_t {
    u32 pid;
    u32 uid;
    char pname[DNAME_INLINE_LEN];   // Parent process name
    char fname[DNAME_INLINE_LEN];   // File being accessed
    char comm[TASK_COMM_LEN];       // Current process comm
    char otype[TASK_COMM_LEN];      // Operation type
    int  is_unauthorized;           // 1 = unauthorized access
    u32  process_inode;             // Inode of accessing process
    u32  file_category;             // Category of file being accessed
};

BPF_PERF_OUTPUT(events);

// Inode-based tracking
BPF_HASH(sensitive_inodes, u64, u64);      // Files to monitor
BPF_HASH(authorized_exec_inodes, u64, u64); // Authorized executables

// Safe reader macro
#define READ_KERN(dst, src) bpf_probe_read_kernel(&(dst), sizeof(dst), src)

static __always_inline void fill_op(char dst[TASK_COMM_LEN], int op)
{
    #pragma unroll
    for (int i = 0; i < TASK_COMM_LEN; i++) dst[i] = 0;

    if (op == 1) { __builtin_memcpy(dst, "READ", 4); }
    if (op == 2) { __builtin_memcpy(dst, "WRITE", 5); }
    if (op == 3) { __builtin_memcpy(dst, "OPEN_W", 6); }
    if (op == 4) { __builtin_memcpy(dst, "RENAME", 6); }
    if (op == 5) { __builtin_memcpy(dst, "DELETE", 6); }
    if (op == 6) { __builtin_memcpy(dst, "CREATE", 6); }
    if (op == 7) { __builtin_memcpy(dst, "EXEC", 4); }
}

// Check if string matches pattern (simplified)
static __always_inline int str_match(const char *str, const char *pattern, int pattern_len)
{
    #pragma unroll
    for (int i = 0; i < pattern_len; i++) {
        if (str[i] != pattern[i]) return 0;
    }
    return 1;
}

// Detect file category from filename
static __always_inline int detect_file_category(const char *fname)
{
    // Check for energy_uj
    if (str_match(fname, "energy_uj", 9)) return FILE_CAT_ENERGY;
    
    // Check for stat (covers /proc/stat and /proc/<pid>/stat)
    if (str_match(fname, "stat", 4)) return FILE_CAT_PROC_STAT;
    
    // Check for cpuinfo
    if (str_match(fname, "cpuinfo", 7)) return FILE_CAT_PROC_CPU;
    
    // Check for meminfo
    if (str_match(fname, "meminfo", 7)) return FILE_CAT_PROC_MEM;
    
    // Check for io (per-process I/O)
    if (fname[0] == 'i' && fname[1] == 'o' && fname[2] == '\0') return FILE_CAT_PROC_IO;
    
    // Check for cmdline
    if (str_match(fname, "cmdline", 7)) return FILE_CAT_PROC_CMD;
    
    // Check for scaphandre binary
    if (str_match(fname, "scaphandre", 10)) return FILE_CAT_BINARY;
    
    return FILE_CAT_UNKNOWN;
}

static __always_inline int safe_get_filename(struct dentry *de, char out[DNAME_INLINE_LEN])
{
    struct qstr dname = {};
    READ_KERN(dname, &de->d_name);

    if (dname.len > DNAME_INLINE_LEN - 1) {
        const char *p = NULL;
        READ_KERN(p, &dname.name);
        if (p) bpf_probe_read_kernel(out, DNAME_INLINE_LEN - 1, p);
        return 0;
    }

    bpf_probe_read_kernel(out, dname.len, de->d_iname);
    return 0;
}

// Main file access handler
static __always_inline int handle_file_access(struct pt_regs *ctx,
                                               struct file *file,
                                               int op,
                                               bool is_write)
{
    if (!file) return 0;

    struct data_t data = {};

    // Read dentry
    struct dentry *de = NULL;
    READ_KERN(de, &file->f_path.dentry);
    if (!de) return 0;

    // Read inode
    struct inode *inode = NULL;
    READ_KERN(inode, &de->d_inode);
    if (!inode) return 0;

    u64 ino = 0;
    READ_KERN(ino, &inode->i_ino);

    // Check if in sensitive list (inode-based)
    u64 *is_sens = sensitive_inodes.lookup(&ino);
    
    // Get filename
    safe_get_filename(de, data.fname);
    
    // Detect file category
    data.file_category = detect_file_category(data.fname);
    
    // If not in inode list and not a known category, skip
    if (!is_sens && data.file_category == FILE_CAT_UNKNOWN) {
        return 0;
    }

    // Get process executable info
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

    // Fill data
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.process_inode = process_inode;
    
    #pragma unroll
    for (int i = 0; i < DNAME_INLINE_LEN; i++) {
        data.pname[i] = pname[i];
    }

    // Authorization check
    int unauthorized = 1;
    
    // Check if process inode is authorized
    if (process_inode != 0) {
        u64 proc_ino_64 = (u64)process_inode;
        u64 *is_authorized = authorized_exec_inodes.lookup(&proc_ino_64);
        if (is_authorized) {
            unauthorized = 0;
        }
    }
    
    // Fallback: check comm name
    if (unauthorized) {
        const char allowed[] = "scaphandre";
        int match = 1;
        
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if (data.comm[i] != allowed[i]) {
                match = 0;
                break;
            }
        }
        if (match) unauthorized = 0;
    }

    // Special rules based on file category
    switch (data.file_category) {
        case FILE_CAT_ENERGY:
            // Energy files: writes always unauthorized (except by scaphandre)
            if (is_write && unauthorized) {
                data.is_unauthorized = 1;
            }
            break;
            
        case FILE_CAT_BINARY:
            // Binary modifications: always report, always unauthorized
            if (is_write) {
                data.is_unauthorized = 1;
            }
            break;
            
        case FILE_CAT_PROC_STAT:
        case FILE_CAT_PROC_CPU:
        case FILE_CAT_PROC_MEM:
        case FILE_CAT_PROC_IO:
        case FILE_CAT_PROC_CMD:
            // /proc files: writes to these are very suspicious
            if (is_write) {
                data.is_unauthorized = 1;
            }
            break;
            
        default:
            // Generic: check inode-based authorization
            data.is_unauthorized = is_write ? unauthorized : 0;
            break;
    }

    fill_op(data.otype, op);

    // Only emit if there's something to report
    if (is_sens || data.is_unauthorized || data.file_category != FILE_CAT_UNKNOWN) {
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

// VFS read hook
int trace_read(struct pt_regs *ctx, struct file *file,
               char __user *buf, size_t count)
{
    return handle_file_access(ctx, file, 1, false);
}

// VFS write hook
int trace_write(struct pt_regs *ctx, struct file *file,
                const char __user *buf, size_t count)
{
    return handle_file_access(ctx, file, 2, true);
}

// Syscall-based openat monitoring for write attempts
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get filename from syscall arguments
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->filename);
    
    // Detect file category
    data.file_category = detect_file_category(data.fname);
    
    // Only interested in write opens to protected files
    int flags = args->flags;
    int is_write_open = (flags & 0x3) != 0;  // O_WRONLY or O_RDWR
    
    if (is_write_open && data.file_category != FILE_CAT_UNKNOWN) {
        // Check authorization by comm name
        const char allowed[] = "scaphandre";
        int match = 1;
        
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if (data.comm[i] != allowed[i]) {
                match = 0;
                break;
            }
        }
        
        if (!match) {
            data.is_unauthorized = 1;
            fill_op(data.otype, 3);  // OPEN_W
            events.perf_submit(args, &data, sizeof(data));
        }
    }
    
    return 0;
}

// Track file renames (potential tampering)
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Read old filename
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->oldname);
    data.file_category = detect_file_category(data.fname);
    
    if (data.file_category != FILE_CAT_UNKNOWN) {
        // Renaming protected files is suspicious
        const char allowed[] = "scaphandre";
        int match = 1;
        
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if (data.comm[i] != allowed[i]) {
                match = 0;
                break;
            }
        }
        
        if (!match) {
            data.is_unauthorized = 1;
            fill_op(data.otype, 4);  // RENAME
            events.perf_submit(args, &data, sizeof(data));
        }
    }
    
    return 0;
}

// Track file deletions
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)args->pathname);
    data.file_category = detect_file_category(data.fname);
    
    if (data.file_category != FILE_CAT_UNKNOWN) {
        // Deleting protected files is always suspicious
        data.is_unauthorized = 1;
        fill_op(data.otype, 5);  // DELETE
        events.perf_submit(args, &data, sizeof(data));
    }
    
    return 0;
}

// Track process execution (for binary integrity)
TRACEPOINT_PROBE(sched, sched_process_exec)
{
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if scaphandre is being executed
    const char target[] = "scaphandre";
    int match = 1;
    
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (comm[i] != target[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        // Log scaphandre execution for audit
        struct data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid();
        __builtin_memcpy(data.comm, comm, TASK_COMM_LEN);
        __builtin_memcpy(data.fname, "scaphandre", 10);
        data.file_category = FILE_CAT_BINARY;
        data.is_unauthorized = 0;  // Just logging execution
        fill_op(data.otype, 7);  // EXEC
        
        events.perf_submit(args, &data, sizeof(data));
    }
    
    return 0;
}

