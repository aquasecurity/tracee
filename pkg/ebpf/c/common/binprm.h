#ifndef __COMMON_BINPRM_H__
#define __COMMON_BINPRM_H__

#include <vmlinux.h>

#include <common/common.h>

static __always_inline const char *get_binprm_filename(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->filename);
}

static __always_inline const char *get_binprm_interp(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->interp);
}

static __always_inline struct file *get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

static __always_inline int get_argc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->argc);
}

static __always_inline int get_envc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->envc);
}

#endif
