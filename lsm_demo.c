#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>

struct security_hook_heads *my_hook_head;

unsigned long clear_and_return_cr0(void);
void setback_cr0(unsigned long val);
void my_init_security_hook_list(void);
static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm);
static void my_del_hooks(struct security_hook_list *hooks, int count);

unsigned long clear_and_return_cr0()
{
	unsigned long cr0 = 0;
	unsigned long ret;
	asm volatile("movq %%cr0,%%rax"
				 : "=a"(cr0));
	ret = cr0;
	cr0 &= 0xfffeffff;
	asm volatile("movq %%rax,%%cr0" ::"a"(cr0));
	return ret;
}

void setback_cr0(unsigned long val)
{
	asm volatile("movq %%rax,%%cr0" ::"a"(val));
}

int my_file_open(struct file *file, const struct cred *cred)
{
	printk("The file opened is %s\n", file->f_path.dentry->d_iname);
	return 0;
}

int my_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	printk("Process mmap file {%s}\n",  file->f_path.dentry->d_name.name);
	return 0;
}

int my_task_alloc(struct task_struct *task,unsigned long clone_flags)
{
    printk("[+geek] call task_create().\n");    
    return 0;
}


struct security_hook_list hooks[2];

void my_init_security_hook_list(void)
{
	union security_list_options my_hook;
	hooks[0].head = &my_hook_head->task_alloc;
	my_hook.task_alloc = my_task_alloc;
	hooks[0].hook = my_hook;
	hooks[1].head = &my_hook_head->file_open;
	my_hook.file_open = my_file_open;
	hooks[1].hook = my_hook;
}


static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm){
	int i;
	for(i = 0; i < count; i++){
		hooks[i].lsm = lsm;
		list_add_tail_rcu(&hooks[i].list, hooks[i].head);
		printk("***************add hooks[%d]*************\n", i);
	}
}

static void my_del_hooks(struct security_hook_list *hooks, int count){
	int i;
	for(i = 0; i < count; i++){
		list_del_rcu((struct list_head *)&hooks[i].list);
		printk("***************del hooks[%d]*************\n", i);
	}
}

static int __init my_init(void)
{
	printk("***************my security start*************\n");

	unsigned long cr0;
	my_hook_head = (struct security_hook_heads *)kallsyms_lookup_name("security_hook_heads");

	my_init_security_hook_list();

	cr0 = clear_and_return_cr0();
	my_add_hooks(hooks, 2,"lsm_demo");
	setback_cr0(cr0);

	return 0;
}

static void __exit my_exit(void)
{
	unsigned long cr0;

	cr0 = clear_and_return_cr0();
	my_del_hooks(hooks, 2);
	setback_cr0(cr0);

	printk("***************my security exit*************\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
