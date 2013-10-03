#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/security.h>

#include "udis86.h"

#define debug(fmt...)			\
	pr_info("[" KBUILD_MODNAME "] " fmt)

/* fake security operations */
static struct security_operations sop;

/* pointer to the system's LSM-model */
static struct security_operations * realsop;

/* pointer to the module's fake LSM-model */
static struct security_operations * fakesop = &sop;

/* pointer to 'security_ops' pointer */
static struct security_operations ** psop = NULL;

static void * get_lsm_entry(void)
{
	/* this one is exported */
	return (void *)&security_sb_copy_data;
}

static struct security_operations ** get_lsm_sop(void)
{
	ud_t ud;
	void * entry = get_lsm_entry(), * result = NULL;

	ud_initialize(&ud, BITS_PER_LONG, UD_VENDOR_ANY, entry, 128);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Imov && \
		    ud.operand[0].type == UD_OP_REG && ud.operand[1].type == UD_OP_MEM)
		{
#ifdef CONFIG_X86_64
			result = entry + ud_insn_off(&ud) + ud_insn_len(&ud);
#endif
			result = result + ud.operand[1].lval.sdword;

			break;
		}
	}

	return result;
}

static int fake_inode_permission(struct inode * inode, int mask)
{
	debug("%s inode:%pK mask:%08x\n", __func__, inode, mask);

	return realsop->inode_permission(inode, mask);
}

int init_module(void)
{
	psop = get_lsm_sop();
	if (!psop) {
		debug("can't find LSM security_ops pointer\n");
		return -EINVAL;
	}

	realsop = *psop;

	memcpy(fakesop, realsop, sizeof(struct security_operations));
	snprintf(fakesop->name, SECURITY_NAME_MAX, "fakesop");

	debug("found LSM security_ops @ %pK (%s)\n", psop, (*psop)->name);

	fakesop->inode_permission = &fake_inode_permission;

	*psop = fakesop;

	debug("initialized\n");

	return 0;
}

void cleanup_module(void)
{
	*psop = realsop;

	debug("deinitialized\n");
}

MODULE_LICENSE	("GPLv2");
MODULE_AUTHOR	("Ilya V. Matveychikov <matvejchikov@gmail.com>");
