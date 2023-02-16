#ifndef __TRACEE_CONSTS_H__
#define __TRACEE_CONSTS_H__

// clang-format off
#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define MAX_BYTES_ARR_SIZE 4096       // max size of bytes array (arbitrarily chosen)
#define MAX_STR_FILTER_SIZE 16        // bounded to size of the compared values (comm)
#define MAX_BIN_PATH_SIZE   256       // max binary path size
#define FILE_MAGIC_HDR_SIZE 32        // magic_write: bytes to save from a file's header
#define FILE_MAGIC_MASK     31        // magic_write: mask used for verifier boundaries
#define NET_SEQ_OPS_SIZE    4         // print_net_seq_ops: struct size - TODO: replace with uprobe argument
#define NET_SEQ_OPS_TYPES   6         // print_net_seq_ops: argument size - TODO: replace with uprobe argument
#define MAX_KSYM_NAME_SIZE  64
#define UPROBE_MAGIC_NUMBER 20220829
#define ARGS_BUF_SIZE       32000
#define SEND_META_SIZE      24
#define MAX_MEM_DUMP_SIZE   127

// clang-format on

#ifndef CORE
    #if LINUX_VERSION_CODE <                                                                       \
        KERNEL_VERSION(5, 2, 0) // lower values in old kernels (instr lim is 4096)
        #define MAX_STR_ARR_ELEM      38
        #define MAX_ARGS_STR_ARR_ELEM 15
        #define MAX_PATH_PREF_SIZE    64
        #define MAX_PATH_COMPONENTS   20
        #define MAX_BIN_CHUNKS        110
    #else // complexity limit of 1M verified instructions
        #define MAX_STR_ARR_ELEM      128
        #define MAX_ARGS_STR_ARR_ELEM 128
        #define MAX_PATH_PREF_SIZE    128
        #define MAX_PATH_COMPONENTS   48
        #define MAX_BIN_CHUNKS        256
    #endif
#else                                // CORE
    #define MAX_STR_ARR_ELEM      38 // TODO: turn this into global variables set w/ libbpfgo
    #define MAX_ARGS_STR_ARR_ELEM 15
    #define MAX_PATH_PREF_SIZE    64
    #define MAX_PATH_COMPONENTS   20
    #define MAX_BIN_CHUNKS        110
#endif

#define CAPTURE_IFACE (1 << 0)
#define TRACE_IFACE   (1 << 1)

#define OPT_EXEC_ENV              (1 << 0)
#define OPT_CAPTURE_FILES         (1 << 1)
#define OPT_EXTRACT_DYN_CODE      (1 << 2)
#define OPT_CAPTURE_STACK_TRACES  (1 << 3)
#define OPT_CAPTURE_MODULES       (1 << 4)
#define OPT_CGROUP_V1             (1 << 5)
#define OPT_PROCESS_INFO          (1 << 6)
#define OPT_TRANSLATE_FD_FILEPATH (1 << 7)

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

#endif // __TRACEE_CONSTS_H__