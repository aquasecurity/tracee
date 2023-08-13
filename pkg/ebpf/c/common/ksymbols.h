#ifndef __COMMON_KSYMBOLS_H__
#define __COMMON_KSYMBOLS_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc void *get_symbol_addr(char *);
statfunc void *get_stext_addr();
statfunc void *get_etext_addr();
statfunc struct pipe_inode_info *get_file_pipe_info(struct file *);

// FUNCTIONS

statfunc void *get_symbol_addr(char *symbol_name)
{
    char new_ksym_name[MAX_KSYM_NAME_SIZE] = {};
    bpf_probe_read_str(new_ksym_name, MAX_KSYM_NAME_SIZE, symbol_name);
    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *) &new_ksym_name);

    if (sym == NULL)
        return 0;

    return *sym;
}

statfunc void *get_stext_addr()
{
    char start_text_sym[7] = "_stext";
    return get_symbol_addr(start_text_sym);
}

statfunc void *get_etext_addr()
{
    char end_text_sym[7] = "_etext";
    return get_symbol_addr(end_text_sym);
}

statfunc struct pipe_inode_info *get_file_pipe_info(struct file *file)
{
    struct pipe_inode_info *pipe = BPF_CORE_READ(file, private_data);
    char pipe_write_sym[11] = "pipe_write";
    void *file_write_iter_op = BPF_CORE_READ(file, f_op, write_iter);

    if (file_write_iter_op != get_symbol_addr(pipe_write_sym))
        return NULL;

    return pipe;
}

#endif
