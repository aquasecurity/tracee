#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>

// Example of a kernel module hijacking a system call.

MODULE_LICENSE("GPL");

ulong table;
module_param(table, ulong, 0);

asmlinkage u64 (*orig_uname)(struct old_utsname *);

asmlinkage u64 hooked_uname(struct old_utsname *name)
{
    printk(KERN_INFO "uname() intercepted!\n");
    return orig_uname(name);
}

#define RO 0
#define RW 1

static int set_page(u64 addr, int flag)
{
    u32 level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte && pte_present(*pte))
        pte->pte = flag ? pte->pte | _PAGE_RW : pte->pte & ~_PAGE_RW;

    return 0;
}

static int __init hijack_init(void)
{
    if (!table)
        return -EINVAL;

    set_page(table, RW);
    orig_uname = (void *) ((u64 **) table)[__NR_uname];
    ((u64 **) table)[__NR_uname] = (u64 *) hooked_uname;
    set_page(table, RO);

    return 0;
}

static void __exit hijack_exit(void)
{
    set_page(table, RW);
    ((u64 **) table)[__NR_uname] = (u64 *) orig_uname;
    set_page(table, RO);
}

module_init(hijack_init);
module_exit(hijack_exit);
