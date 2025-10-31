#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

static char *symbol = "commit_creds";
module_param(symbol, charp, 0000);
MODULE_PARM_DESC(symbol, "The symbol to hook");

static struct kprobe kp;
static bool intercepted_once = false;

/* Handler for pre-kprobe (executed just before the probed instruction) */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    if (!intercepted_once) {
        pr_info("hooker: commit_creds() intercepted!\n");
        intercepted_once = true;
    }

    return 0;
}

static int __init hooker_init(void)
{
    int ret;

    kp.symbol_name = symbol;
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("hooker: register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("hooker: Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit hooker_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("hooker: kprobe at %p unregistered\n", kp.addr);
}

module_init(hooker_init);
module_exit(hooker_exit);
