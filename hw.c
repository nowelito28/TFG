/**
 * @file    hello.c
 * @author  Akshat Sinha
 * @date    10 Sept 2016
 * @version 0.1
 * @brief  An introductory "Hello World!" loadable kernel
 *  module (LKM) that can display a message in the /var/log/kern.log
 *  file when the module is loaded and removed. The module can accept
 *  an argument when it is loaded -- the name, which appears in the
 *  kernel log files.        
*/
#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */

///< The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");

///< The author -- visible when you use modinfo
MODULE_AUTHOR("Noel Rodriguez Perez");

///< The description -- see modinfo
MODULE_DESCRIPTION("A simple Hello world LKM!");

///< The version of the module
MODULE_VERSION("0.1");

///< Kernel modules must have at least two functions:

///< "start" (initialization) function --> init_module()
///< which is called when the module is insmoded (unedit) into the kernel
static int __init hello_start(void)
{
    ///< "printk" prints (logs) messages in /var/log/kern.log => NOT IN CONSOLE -> DEBUG
    ///< "printf" => system call
    ///< in admin level (kernel) we do not have them, only at user level
    printk(KERN_INFO "Loading hello module...\n");
    printk(KERN_INFO "Hello world!!\n");
    return 0;
}

///< "end" (cleanup) function --> cleanup_module()
///< which is called just before it is rmmoded (modified)
static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye Mr.\n");
}


///< Control flow of the LKM
module_init(hello_start);
module_exit(hello_end);
