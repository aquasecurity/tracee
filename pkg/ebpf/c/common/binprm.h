#ifndef __COMMON_BINPRM_H__
#define __COMMON_BINPRM_H__

#include <vmlinux.h>

#include <common/common.h>

// PROTOTYPES

statfunc const char *get_binprm_filename(struct linux_binprm *);
statfunc const char *get_binprm_interp(struct linux_binprm *);
statfunc struct file *get_file_ptr_from_bprm(struct linux_binprm *);
statfunc int get_argc_from_bprm(struct linux_binprm *);
statfunc int get_envc_from_bprm(struct linux_binprm *);

// FUNCTIONS

statfunc const char *get_binprm_filename(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->filename);
}

statfunc const char *get_binprm_interp(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->interp);
}

statfunc struct file *get_file_ptr_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->file);
}

statfunc int get_argc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->argc);
}

statfunc int get_envc_from_bprm(struct linux_binprm *bprm)
{
    return READ_KERN(bprm->envc);
}

#endif
