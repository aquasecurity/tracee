#ifndef __TRACEE_KSYMBOLS_H__
#define __TRACEE_KSYMBOLS_H__

#include "common/consts.h"
#include "common/common.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"

// DECLARATIONS -----------------------------------------------------------------------------------

static __always_inline void *get_symbol_addr(char *symbol_name);
static __always_inline void *get_stext_addr();
static __always_inline void *get_etext_addr();
static __always_inline struct pipe_inode_info *get_file_pipe_info(struct file *file);

// IMPLEMENTATIONS -----------------------------------------------------------------------------------

static __always_inline void *get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *) &new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}

static __always_inline void *get_stext_addr()
{
    char start_text_sym[7] = "_stext";
    return get_symbol_addr(start_text_sym);
}

static __always_inline void *get_etext_addr()
{
    char end_text_sym[7] = "_etext";
    return get_symbol_addr(end_text_sym);
}

static __always_inline struct pipe_inode_info *get_file_pipe_info(struct file *file)
{
    struct pipe_inode_info *pipe = READ_KERN(file->private_data);
    char pipe_fops_sym[14] = "pipefifo_fops";
    if (READ_KERN(file->f_op) != get_symbol_addr(pipe_fops_sym)) {
        return NULL;
    }
    return pipe;
}

#endif