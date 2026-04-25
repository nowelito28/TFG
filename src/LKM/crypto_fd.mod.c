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
	{ 0xa61fd7aa, "__check_object_size" },
	{ 0x092a35a2, "_copy_to_user" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x1c3ccb5e, "proc_remove" },
	{ 0xa53f4e29, "memcpy" },
	{ 0x737dbace, "crypto_alloc_shash" },
	{ 0x6b473f6a, "crypto_shash_setkey" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0x57daafd5, "crypto_shash_digest" },
	{ 0xff746880, "crypto_destroy_tfm" },
	{ 0x27683a56, "memset" },
	{ 0x092a35a2, "_copy_from_user" },
	{ 0x9479a1e8, "strnlen" },
	{ 0xd09b06f5, "kstrtoint" },
	{ 0x361ef55d, "fget" },
	{ 0xe86eaf92, "inode_permission" },
	{ 0xd710adbf, "__kmalloc_large_noprof" },
	{ 0xe9372d44, "init_task" },
	{ 0xe046abb1, "init_user_ns" },
	{ 0x7d33ff89, "from_kuid" },
	{ 0x40a621c5, "snprintf" },
	{ 0x4dd5dc89, "get_task_cred" },
	{ 0x2cd42066, "task_active_pid_ns" },
	{ 0x34682121, "__task_pid_nr_ns" },
	{ 0xea707533, "from_kgid" },
	{ 0xf4c3fbcd, "d_path" },
	{ 0x4986679e, "base64_encode" },
	{ 0x884b1b6d, "kernel_write" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x6b89f425, "__put_cred" },
	{ 0xc689cda3, "fput" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xd272d446, "__fentry__" },
	{ 0x73369fdb, "proc_create" },
	{ 0xe8213e80, "_printk" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0x546c19d9, "validate_usercopy_range" },
	{ 0x00bc5fb3, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xa61fd7aa,
	0x092a35a2,
	0xd272d446,
	0x1c3ccb5e,
	0xa53f4e29,
	0x737dbace,
	0x6b473f6a,
	0xd710adbf,
	0x57daafd5,
	0xff746880,
	0x27683a56,
	0x092a35a2,
	0x9479a1e8,
	0xd09b06f5,
	0x361ef55d,
	0xe86eaf92,
	0xd710adbf,
	0xe9372d44,
	0xe046abb1,
	0x7d33ff89,
	0x40a621c5,
	0x4dd5dc89,
	0x2cd42066,
	0x34682121,
	0xea707533,
	0xf4c3fbcd,
	0x4986679e,
	0x884b1b6d,
	0xcb8b6ec6,
	0x6b89f425,
	0xc689cda3,
	0xe54e0a6b,
	0xd272d446,
	0x73369fdb,
	0xe8213e80,
	0xd272d446,
	0xbd03ed67,
	0x546c19d9,
	0x00bc5fb3,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__check_object_size\0"
	"_copy_to_user\0"
	"__stack_chk_fail\0"
	"proc_remove\0"
	"memcpy\0"
	"crypto_alloc_shash\0"
	"crypto_shash_setkey\0"
	"__kmalloc_noprof\0"
	"crypto_shash_digest\0"
	"crypto_destroy_tfm\0"
	"memset\0"
	"_copy_from_user\0"
	"strnlen\0"
	"kstrtoint\0"
	"fget\0"
	"inode_permission\0"
	"__kmalloc_large_noprof\0"
	"init_task\0"
	"init_user_ns\0"
	"from_kuid\0"
	"snprintf\0"
	"get_task_cred\0"
	"task_active_pid_ns\0"
	"__task_pid_nr_ns\0"
	"from_kgid\0"
	"d_path\0"
	"base64_encode\0"
	"kernel_write\0"
	"kfree\0"
	"__put_cred\0"
	"fput\0"
	"__fortify_panic\0"
	"__fentry__\0"
	"proc_create\0"
	"_printk\0"
	"__x86_return_thunk\0"
	"__ref_stack_chk_guard\0"
	"validate_usercopy_range\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "CE86434BFDD7627658989F3");
