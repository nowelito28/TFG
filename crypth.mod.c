#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x122c3a7e, "_printk" },
	{ 0xadf70bd6, "proc_remove" },
	{ 0x742578a5, "wait_for_random_bytes" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x479803b9, "base64_encode" },
	{ 0x3c3f868, "proc_create" },
	{ 0xdcb764ad, "memset" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x6cbbfc54, "__arch_copy_to_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x5f2f7d7e, "crypto_alloc_shash" },
	{ 0xfc940650, "crypto_shash_setkey" },
	{ 0x52c5c991, "__kmalloc_noprof" },
	{ 0x37a0cba, "kfree" },
	{ 0x5984a61b, "crypto_destroy_tfm" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0xdec674af, "crypto_shash_update" },
	{ 0x4e270fb4, "crypto_shash_final" },
	{ 0x4829a47e, "memcpy" },
	{ 0x96d437aa, "fget" },
	{ 0xe69f9c9c, "kernel_write" },
	{ 0xd5b0ccd3, "fput" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0x98cf60b3, "strlen" },
	{ 0xd2352f3a, "param_ops_int" },
	{ 0xa07cd3, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "C43E7509698731EC148E299");
