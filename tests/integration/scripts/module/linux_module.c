#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tester");
MODULE_DESCRIPTION("Module for triggering security_kernel_read_file/security_kernel_post_read_file");

static int __init mod_init(void) {
    printk(KERN_INFO "Module loaded.\n");
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "Module unloaded.\n");
}

module_init(mod_init);
module_exit(mod_exit);
