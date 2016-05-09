/*
 * Copyright (c) 2016, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smaf-secure.h>

#define MAGIC 0xDEADBEEF

struct fake_private {
	int magic;
};

static void *smaf_fakesecure_create(void)
{
	struct fake_private *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	priv->magic = MAGIC;

	return priv;
}

static int smaf_fakesecure_destroy(void *ctx)
{
	struct fake_private *priv = (struct fake_private *)ctx;

	WARN_ON(!priv || (priv->magic != MAGIC));
	kfree(priv);

	return 0;
}

static bool smaf_fakesecure_grant_access(void *ctx,
					 struct device *dev,
					 size_t addr, size_t size,
					 enum dma_data_direction direction)
{
	struct fake_private *priv = (struct fake_private *)ctx;

	WARN_ON(!priv || (priv->magic != MAGIC));

	return priv->magic == MAGIC;
}

static void smaf_fakesecure_revoke_access(void *ctx,
					  struct device *dev,
					  size_t addr, size_t size,
					  enum dma_data_direction direction)
{
	struct fake_private *priv = (struct fake_private *)ctx;

	WARN_ON(!priv || (priv->magic != MAGIC));
}

static bool smaf_fakesecure_allow_cpu_access(void *ctx,
					     enum dma_data_direction direction)
{
	struct fake_private *priv = (struct fake_private *)ctx;

	WARN_ON(!priv || (priv->magic != MAGIC));

	return priv->magic == MAGIC;
}

static struct smaf_secure fake = {
	.create_ctx = smaf_fakesecure_create,
	.destroy_ctx = smaf_fakesecure_destroy,
	.grant_access = smaf_fakesecure_grant_access,
	.revoke_access = smaf_fakesecure_revoke_access,
	.allow_cpu_access = smaf_fakesecure_allow_cpu_access,
};

static int __init smaf_fakesecure_init(void)
{
	return smaf_register_secure(&fake);
}
module_init(smaf_fakesecure_init);

static void __exit smaf_fakesecure_deinit(void)
{
	smaf_unregister_secure(&fake);
}
module_exit(smaf_fakesecure_deinit);

MODULE_DESCRIPTION("SMAF OP-TEE secure module");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Pascal Brand <pascal.brand@linaro.org>");
