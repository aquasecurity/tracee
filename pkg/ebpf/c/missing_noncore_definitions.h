
// cannot include trace/trace_probe.h

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
typedef void (*fetch_func_t)(struct pt_regs *, void *, void *);
typedef int (*print_type_func_t)(struct trace_seq *, const char *, void *, void *);

enum
{
    FETCH_MTD_reg = 0,
    FETCH_MTD_stack,
    FETCH_MTD_retval,
    FETCH_MTD_comm,
    FETCH_MTD_memory,
    FETCH_MTD_symbol,
    FETCH_MTD_deref,
    FETCH_MTD_bitfield,
    FETCH_MTD_file_offset,
    FETCH_MTD_END,
};

struct fetch_type {
    const char *name;        /* Name of type */
    size_t size;             /* Byte size of type */
    int is_signed;           /* Signed flag */
    print_type_func_t print; /* Print functions */
    const char *fmt;         /* Fromat string */
    const char *fmttype;     /* Name in format file */
    /* Fetch functions */
    fetch_func_t fetch[FETCH_MTD_END];
};

struct fetch_param {
    fetch_func_t fn;
    void *data;
};

struct probe_arg {
    struct fetch_param fetch;
    struct fetch_param fetch_size;
    unsigned int offset;           /* Offset from argument entry */
    const char *name;              /* Name of this argument */
    const char *comm;              /* Command of this argument */
    const struct fetch_type *type; /* Type of this argument */
};

struct trace_probe {
    unsigned int flags; /* For TP_FLAG_* */
    struct trace_event_class class;
    struct trace_event_call call;
    struct list_head files;
    ssize_t size; /* trace entry size */
    unsigned int nr_args;
    struct probe_arg args[];
};

#else

    #include <linux/seq_buf.h>
    #include <linux/trace_seq.h>

typedef int (*print_type_func_t)(struct trace_seq *, void *, void *);

enum fetch_op
{
    FETCH_OP_NOP = 0,
    // Stage 1 (load) ops
    FETCH_OP_REG,    /* Register : .param = offset */
    FETCH_OP_STACK,  /* Stack : .param = index */
    FETCH_OP_STACKP, /* Stack pointer */
    FETCH_OP_RETVAL, /* Return value */
    FETCH_OP_IMM,    /* Immediate : .immediate */
    FETCH_OP_COMM,   /* Current comm */
    FETCH_OP_ARG,    /* Function argument : .param */
    FETCH_OP_FOFFS,  /* File offset: .immediate */
    FETCH_OP_DATA,   /* Allocated data: .data */
    // Stage 2 (dereference) op
    FETCH_OP_DEREF,  /* Dereference: .offset */
    FETCH_OP_UDEREF, /* User-space Dereference: .offset */
    // Stage 3 (store) ops
    FETCH_OP_ST_RAW,     /* Raw: .size */
    FETCH_OP_ST_MEM,     /* Mem: .offset, .size */
    FETCH_OP_ST_UMEM,    /* Mem: .offset, .size */
    FETCH_OP_ST_STRING,  /* String: .offset, .size */
    FETCH_OP_ST_USTRING, /* User String: .offset, .size */
    // Stage 4 (modify) op
    FETCH_OP_MOD_BF, /* Bitfield: .basesize, .lshift, .rshift */
    // Stage 5 (loop) op
    FETCH_OP_LP_ARRAY, /* Array: .param = loop count */
    FETCH_OP_END,
    FETCH_NOP_SYMBOL, /* Unresolved Symbol holder */
};

struct fetch_insn {
    enum fetch_op op;
    union {
        unsigned int param;
        struct {
            unsigned int size;
            int offset;
        };
        struct {
            unsigned char basesize;
            unsigned char lshift;
            unsigned char rshift;
        };
        unsigned long immediate;
        void *data;
    };
};

struct fetch_type {
    const char *name;        /* Name of type */
    size_t size;             /* Byte size of type */
    int is_signed;           /* Signed flag */
    print_type_func_t print; /* Print functions */
    const char *fmt;         /* Fromat string */
    const char *fmttype;     /* Name in format file */
};

struct probe_arg {
    struct fetch_insn *code;
    bool dynamic;                  /* Dynamic array (string) is used */
    unsigned int offset;           /* Offset from argument entry */
    unsigned int count;            /* Array count */
    const char *name;              /* Name of this argument */
    const char *comm;              /* Command of this argument */
    char *fmt;                     /* Format string if needed */
    const struct fetch_type *type; /* Type of this argument */
};

struct trace_probe_event {
    unsigned int flags; /* For TP_FLAG_* */
    struct trace_event_class class;
    struct trace_event_call call;
    struct list_head files;
    struct list_head probes;
};

struct trace_probe {
    struct list_head list;
    struct trace_probe_event *event;
    ssize_t size; /* trace entry size */
    unsigned int nr_args;
    struct probe_arg args[];
};

#endif

// cannot include trace/trace_kprobe.c

struct trace_kprobe {
    struct list_head list;
    struct kretprobe rp; /* Use rp.kp for kprobe use */
    unsigned long __percpu *nhit;
    const char *symbol; /* symbol name */
    struct trace_probe tp;
};

// cannot include trace/trace_uprobe.c

struct trace_uprobe_filter {
    rwlock_t rwlock;
    int nr_systemwide;
    struct list_head perf_events;
};

struct trace_uprobe {
    struct list_head list;
    struct trace_uprobe_filter filter;
    struct uprobe_consumer consumer;
    struct path path;
    struct inode *inode;
    char *filename;
    unsigned long offset;
    unsigned long nhit;
    struct trace_probe tp;
};
