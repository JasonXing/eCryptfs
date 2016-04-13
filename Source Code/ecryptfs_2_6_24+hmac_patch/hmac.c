/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2007 Trevor Highland
 *   Author(s): Trevor S. Highland <trevor.highland@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include "ecryptfs_kernel.h"

struct kmem_cache *ecryptfs_extent_cache;

#define HEADER_EXTENTS ( (crypt_stat->num_header_bytes_at_front) \
			 / (crypt_stat->extent_size))
#define FL_HMAC(extent) (((extent) & 0x1fc000) >> 14)/*(1111111) 111111100000000000000>>14*/
#define SL_HMAC(extent) (((extent) & 0x3f80) >> 7)/*(1111111) 11111110000000>>7*/
#define TL_HMAC(extent) ((extent) & 0x7f)/*1111111*/
#define FL_OFFSET (HMAC_PER_EXTENT * (HMAC_PER_EXTENT + 1) + 1)/*First level(16513): 128*(128+1)+1)*/
#define SL_OFFSET (HMAC_PER_EXTENT + 1)/*Second level(129): 128+1*/
int ecryptfs_init_hmac(struct ecryptfs_crypt_stat *crypt_stat)
{
	int rc = 0;

	mutex_init(&crypt_stat->cs_hmac_tfm_mutex);
	mutex_init(&crypt_stat->cs_hmac_mutex);
	crypt_stat->root = kzalloc(sizeof(struct ecryptfs_hmac_table),
				   GFP_KERNEL);
	if (!(crypt_stat->root)) {
		rc = -ENOMEM;
		goto out;
	}
	crypt_stat->root->extent =
			kmem_cache_zalloc(ecryptfs_extent_cache, GFP_KERNEL);/*4096*/
	if (!(crypt_stat->root)) {
		rc = -ENOMEM;
		goto out;
	}
	crypt_stat->hmac_bytes = ECRYPTFS_HMAC_BYTES/* 32 */;
	if (strlen(ECRYPTFS_DEFAULT_HMAC) <= ECRYPTFS_MAX_CIPHER_NAME_SIZE) {
		strcpy(crypt_stat->hmac, ECRYPTFS_DEFAULT_HMAC);
	}
out:
	return rc;
}

static int ecryptfs_read_hmac_root(struct inode *ecryptfs_inode/*src*/,
				   struct ecryptfs_crypt_stat *crypt_stat/*dst*/)
{
	int rc;
	char *extent;

	extent = kmalloc(crypt_stat->extent_size, GFP_KERNEL);
	rc = ecryptfs_read_lower(extent, 0, crypt_stat->extent_size,
				 ecryptfs_inode);
	if (rc)
		goto out;
	memcpy(crypt_stat->root->extent,
			&extent[crypt_stat->root_hmac_header_offset],
			2 * crypt_stat->hmac_bytes/*32*/);

	kfree(extent);

out:
	return rc;
}

static int ecryptfs_write_hmac_root_to_header(struct inode *ecryptfs_inode,
					      struct ecryptfs_crypt_stat *crypt_stat)
{
	int rc;
	loff_t offset = crypt_stat->root_hmac_header_offset;
	struct ecryptfs_hmac_table *root;

	root = crypt_stat->root;
	if (crypt_stat->flags & ECRYPTFS_ROOT_HMAC)
		offset += crypt_stat->hmac_bytes;
	rc = ecryptfs_write_lower(ecryptfs_inode, root->extent, offset,
				  crypt_stat->hmac_bytes/*32*/);
	crypt_stat->flags ^= ECRYPTFS_ROOT_HMAC;
	return rc;
}

/*
 * For performance reasons, hmac extents reside in memory until the file is
 * closed.  This functions flushes each of the hmac extents to disk.
 */
int ecryptfs_hmac_close(struct inode *ecryptfs_inode)
{
	int rc = 0;
	size_t i;
	size_t j;
	loff_t offset;
	struct ecryptfs_crypt_stat *crypt_stat;
	struct ecryptfs_hmac_table *root;

	crypt_stat = (&ecryptfs_inode_to_private(ecryptfs_inode)->crypt_stat);

	mutex_lock(&crypt_stat->cs_hmac_mutex);
	root = crypt_stat->root;
	if(!root) {
		rc = -EIO;
		goto out;
	}
	for (i = 0; i < HMAC_PER_EXTENT; i++) {
		if (!root->children[i])
			break;
		if (!(root->children[i]->flags & ECRYPTFS_HMAC_EXTENT_DIRTY)) {
			continue;
		}
		for (j = 0; j < HMAC_PER_EXTENT; j++) {
			if (!root->children[i]->children[j])
				break;
			if (!(root->children[i]->children[j]->flags
					& ECRYPTFS_HMAC_EXTENT_DIRTY)) {
				continue;
			}
			offset = root->children[i]->children[j]->lwr_extent
				 * crypt_stat->extent_size;
			rc = ecryptfs_write_lower(ecryptfs_inode/*dst*/,
					root->children[i]->children[j]->extent/*data*/,
					offset, crypt_stat->extent_size);
			if (rc) {
				ecryptfs_printk(KERN_ERR, "Error, writing hmac "
						"extent. returning EIO\n");
				rc = -EIO;
				goto out;
			}
		}
		offset = root->children[i]->lwr_extent
				* crypt_stat->extent_size;
		rc = ecryptfs_write_lower(ecryptfs_inode,
					  root->children[i]->extent,
					  offset, crypt_stat->extent_size);
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error, writing hmac extent. "
						"returning EIO\n");
			rc = -EIO;
			goto out;
		}
	}
out:
	mutex_unlock(&crypt_stat->cs_hmac_mutex);
	return rc;
}

static int ecryptfs_calculate_root_hmac(struct ecryptfs_crypt_stat *crypt_stat,
					char *dst)
{
	struct hash_desc desc = {
		.tfm = crypt_stat->hmac_tfm,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP,
	};
	struct ecryptfs_hmac_table *root;
	struct scatterlist sg;
	size_t i;
	int rc;

	mutex_lock(&crypt_stat->cs_hmac_tfm_mutex);
	root = crypt_stat->root;
	if(!root) {
		rc = -EIO;
		goto out;
	}
	if (!desc.tfm) {
		desc.tfm = crypto_alloc_hash(crypt_stat->hmac, 0,
				CRYPTO_ALG_ASYNC);
		if (IS_ERR(desc.tfm)) {
			rc = PTR_ERR(desc.tfm);
			ecryptfs_printk(KERN_ERR, "Error attempting to "
					"allocate crypto context; rc = [%d]\n",
					rc);
			goto out;
		}
		rc = crypto_hash_setkey(desc.tfm, crypt_stat->key,
				crypt_stat->key_size);
		if (rc) {
			ecryptfs_printk(KERN_ERR, "Error setting hmac key [%d]",
					rc);
			goto out;
		}
		crypt_stat->hmac_tfm = desc.tfm;
	}

	crypto_hash_init(&desc);
	for (i=0; i < HMAC_PER_EXTENT/*128*/; i++) {
		if (!root->children[i])
			break;
		sg_init_one(&sg, root->children[i]->extent,
			    crypt_stat->extent_size);
		crypto_hash_update(&desc, &sg, crypt_stat->extent_size);
	}
	crypto_hash_final(&desc, dst);
out:
	mutex_unlock(&crypt_stat->cs_hmac_tfm_mutex);
	return rc;
}

static int ecryptfs_init_hmac_node(struct ecryptfs_hmac_table **hmac_node,
				   size_t lwr_extent)
{
	int rc = 0;
	*hmac_node = kzalloc(sizeof(struct ecryptfs_hmac_table),GFP_KERNEL);
	if (!(*hmac_node)) {
		rc = -ENOMEM;
		goto out;
	}
	(*hmac_node)->lwr_extent = lwr_extent;
	(*hmac_node)->extent =
		kmem_cache_zalloc(ecryptfs_extent_cache, GFP_KERNEL);/*4096*/
	if (!((*hmac_node)->extent)) {
		rc = -ENOMEM;
		goto out;
	}
out:
	return rc;
}

int ecryptfs_verify_root_hmac(struct ecryptfs_crypt_stat *crypt_stat,
			      struct inode *ecryptfs_inode)
{
	int rc = 0;
	size_t i;
	size_t lwr_extent;
	u64 file_size;
	struct ecryptfs_hmac_table *root;
	char *root_hmac;


	root_hmac = kzalloc(ECRYPTFS_HMAC_BYTES/*32*/, GFP_KERNEL);
	if (!root_hmac) {
		ecryptfs_printk(KERN_ERR, "Error allocating root_hmac\n");
		return -ENOMEM;
	}

	mutex_lock(&crypt_stat->cs_hmac_mutex);
	root = crypt_stat->root;
	if (!root) {
		rc = -EIO;
		goto out;
	}
	ecryptfs_read_hmac_root(ecryptfs_inode/*src*/, crypt_stat/*dst*/);

	/*
	 * Allocate first level HMAC nodes that have not been
	 * prviously initialized
	 */
	file_size = (u64)i_size_read(ecryptfs_inode);
	for (i=0; i<HMAC_PER_EXTENT; i++) {
		if (root->children[i])
			continue;
		if (file_size <= crypt_stat->extent_size * HMAC_PER_EXTENT
				* HMAC_PER_EXTENT * i)
			break;
		lwr_extent = HEADER_EXTENTS + (i * FL_OFFSET);
		rc = ecryptfs_init_hmac_node(&(root->children[i]), lwr_extent);
		if (rc)
			goto out;
		rc = ecryptfs_read_lower(root->children[i]->extent,
					 lwr_extent * crypt_stat->extent_size,
					 crypt_stat->extent_size,
					 ecryptfs_inode);
		if (rc)
			goto out;
	}
	ecryptfs_calculate_root_hmac(crypt_stat, root_hmac/*32*/);
	if (!memcmp(root_hmac, crypt_stat->root->extent, ECRYPTFS_HMAC_BYTES)) {
		crypt_stat->flags |= ECRYPTFS_ROOT_HMAC;
		goto out;
	}
	if (!memcmp(root_hmac, crypt_stat->root->extent + ECRYPTFS_HMAC_BYTES,
		    ECRYPTFS_HMAC_BYTES)) {
		crypt_stat->flags &= ~ECRYPTFS_ROOT_HMAC;
		goto out;
	}
	ecryptfs_printk(KERN_ERR, "HMAC incorrect; return -EIO \n");
	rc = -EIO;
out:
	mutex_unlock(&crypt_stat->cs_hmac_mutex);
	kfree(root_hmac);
	return rc;
}

static int load_hmac_extents(struct ecryptfs_crypt_stat *crypt_stat, int extent,
			     struct inode *ecryptfs_inode)
{
	int rc = 0;
	size_t lwr_extent;
	u64 file_size;
	char *hmac_addr;
	char *hmac_value;
	struct scatterlist sg;
	struct ecryptfs_hmac_table *level1_node;
	struct ecryptfs_hmac_table *level2_node;
	struct ecryptfs_hmac_table *root;

	hmac_value = kmalloc(ECRYPTFS_HMAC_BYTES, GFP_KERNEL);/*32*/
	if (!hmac_value) {
		ecryptfs_printk(KERN_ERR, "Error allocating hmac_value\n");
		return -ENOMEM;
	}

	root = crypt_stat->root;
	if (!root) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		rc = -EIO;
		goto out;
	}
	/*
	 * Allocate first level HMAC node if it has not been
	 * prviously initialized
	 */
	if (!(root->children[FL_HMAC(extent)])) {
		lwr_extent = HEADER_EXTENTS + (FL_HMAC(extent) * FL_OFFSET);
		rc = ecryptfs_init_hmac_node(&(root->children[FL_HMAC(extent)]),
					     lwr_extent);
		if (rc)
			goto out;
		level1_node = root->children[FL_HMAC(extent)];
	} else {
		level1_node = root->children[FL_HMAC(extent)];
	}

	/*
	 * Allocate second level HMAC node if it has not been
	 * previously initialized
	 */
	if (!(level1_node->children[SL_HMAC(extent)])) {
		lwr_extent = (level1_node->lwr_extent + 1)
				+ (SL_HMAC(extent) * SL_OFFSET);
		rc = ecryptfs_init_hmac_node(
				&(level1_node->children[SL_HMAC(extent)]),
				lwr_extent);
		if (rc)
			goto out;
		level2_node = level1_node->children[SL_HMAC(extent)];
		file_size = (u64)i_size_read(ecryptfs_inode);/*inode->i_size*/
		if (file_size <= crypt_stat->extent_size * (extent & ~0x7f)) {
			goto out;
		}
		rc = ecryptfs_read_lower(level2_node->extent/*dst: data*/,
					 lwr_extent * crypt_stat->extent_size/*offset*/,
					 crypt_stat->extent_size/*size*/,
					 ecryptfs_inode);
		if (rc)
			goto out;
		
		/* Below: To verify two value @hmac_value(1st level hmac) and @hmac_addr, use different ways to compute and check */
		sg_init_one(&sg, level2_node->extent, crypt_stat->extent_size);
		rc = ecryptfs_calculate_hmac(hmac_value/*dst: 32octets*/, crypt_stat, &sg,
					     crypt_stat->extent_size);/* Calculate tha value of second level extent hmac */
		if (rc)
			goto out;
		hmac_addr = level1_node->extent
				+ (SL_HMAC(extent) * ECRYPTFS_HMAC_BYTES);/* first level HMAC value */
		if (memcmp(hmac_value, hmac_addr, ECRYPTFS_HMAC_BYTES)) {
			ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
			rc = -EIO;
			goto out;
		}
	}
out:
	kfree(hmac_value);
	return rc;
}

int ecryptfs_update_hmac(struct ecryptfs_crypt_stat *crypt_stat,
			 struct inode *ecryptfs_inode, struct page *page,
			 int page_offset/*offset in that page*/, int extent/*extent offset*/)
{
	int rc;
	struct ecryptfs_hmac_table *level1_node;
	struct ecryptfs_hmac_table *level2_node;
	struct scatterlist sg;
	char *hmac_addr;


	mutex_lock(&crypt_stat->cs_hmac_mutex);
	if (!crypt_stat->root) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		rc = -EIO;
		goto out;
	}
	rc = load_hmac_extents(crypt_stat, extent, ecryptfs_inode);/*verify the hmac value*/
	if (rc)
		goto out;
	if (!(crypt_stat->root->children[FL_HMAC(extent)])) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		rc = -EIO;
		goto out;
	}
	level1_node = crypt_stat->root->children[FL_HMAC(extent)];

	if (!(level1_node->children[SL_HMAC(extent)])) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		rc = -EIO;
	}
	level2_node = level1_node->children[SL_HMAC(extent)];

	/*
	 * Update the Second level HMAC
	 */
	hmac_addr = level2_node->extent
			+ (TL_HMAC(extent) * ECRYPTFS_HMAC_BYTES);
	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, crypt_stat->extent_size, page_offset);
	rc = ecryptfs_calculate_hmac(hmac_addr/*dst*/, crypt_stat, &sg,
				     crypt_stat->extent_size);
	level2_node->flags |= ECRYPTFS_HMAC_EXTENT_DIRTY;

	/*
	 * Update the first level HMAC
	 */
	hmac_addr = level1_node->extent
			+ (SL_HMAC(extent) * ECRYPTFS_HMAC_BYTES);
	sg_init_one(&sg, level2_node->extent, crypt_stat->extent_size);
	rc = ecryptfs_calculate_hmac(hmac_addr/*dst*/, crypt_stat, &sg,
				     crypt_stat->extent_size);
	if (rc)
		goto out;
	level1_node->flags |= ECRYPTFS_HMAC_EXTENT_DIRTY;
	ecryptfs_calculate_root_hmac(crypt_stat, crypt_stat->root->extent/*dst*/);
	ecryptfs_write_hmac_root_to_header(ecryptfs_inode, crypt_stat);
out:
	mutex_unlock(&crypt_stat->cs_hmac_mutex);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		rc = -EIO;
	}
	return rc;
}

int ecryptfs_verify_hmac(struct ecryptfs_crypt_stat *crypt_stat,
			 struct inode *ecryptfs_inode, struct page *page,
			 int page_offset, int extent)
{
	int rc;
	struct ecryptfs_hmac_table *root;
	struct ecryptfs_hmac_table *node;
	struct scatterlist sg;
	char *hmac_value;
	char *hmac_addr;

	hmac_value = kmalloc(ECRYPTFS_HMAC_BYTES, GFP_KERNEL);/*32*/
	if (!hmac_value) {
		ecryptfs_printk(KERN_ERR, "Error allocating hmac_value\n");
		return -ENOMEM;
	}

	mutex_lock(&crypt_stat->cs_hmac_mutex);
	root = crypt_stat->root;
	if (!root) {
		rc = -EIO;
		goto out;
	}
	rc = load_hmac_extents(crypt_stat, extent, ecryptfs_inode);
	if (rc) {
		goto out;
	}
	if (!(crypt_stat->root->children[FL_HMAC(extent)])) {
		rc = -EINVAL;
		goto out;
	}

	if (!(root->children[FL_HMAC(extent)]->children[SL_HMAC(extent)])) {
		rc = -EINVAL;
		goto out;
	}
	node = root->children[FL_HMAC(extent)]->children[SL_HMAC(extent)];

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, crypt_stat->extent_size, page_offset);
	rc = ecryptfs_calculate_hmac(hmac_value/*dst*/, crypt_stat, &sg,
				     crypt_stat->extent_size);
	if (rc)
		goto out;
	hmac_addr = node->extent + (TL_HMAC(extent) * ECRYPTFS_HMAC_BYTES);
	if (memcmp(hmac_value, hmac_addr, ECRYPTFS_HMAC_BYTES)) {/* Compare 3rd level hmac value */
		rc = -EINVAL;
		goto out;
	}
out:
	mutex_unlock(&crypt_stat->cs_hmac_mutex);
	if (rc) {
		ecryptfs_printk(KERN_ERR, "Error returning EIO\n");
		return -EIO;
	}
	return rc;
}

void ecryptfs_truncate_hmac(struct ecryptfs_crypt_stat *crypt_stat,
			    struct inode *ecryptfs_inode)
{
	struct ecryptfs_hmac_table *root;
	struct ecryptfs_hmac_table *first_level_node;
	size_t size;
	size_t num_extents;
	size_t i;
	size_t j;

	size = i_size_read(ecryptfs_inode);
	num_extents = size / crypt_stat->extent_size;
	i = FL_HMAC((num_extents + 1));
	j = SL_HMAC((num_extents + 1));
	mutex_lock(&crypt_stat->cs_hmac_mutex);
	root = crypt_stat->root;
	if (!root) {
		goto out;
	}
	if (j != 0) {
		first_level_node = root->children[i];
		if (!first_level_node) {
			goto out;
		}
		for (; j < HMAC_PER_EXTENT; j++) {
			if (!first_level_node->children[j])
				goto out;
			kmem_cache_free(ecryptfs_extent_cache,
					first_level_node->children[j]->extent);/*4096*/
			kfree(first_level_node->children[j]);
			memset(&(first_level_node->children[j]), 0,
					sizeof(struct ecryptfs_hmac_table *));
		}
		i++;
	}
	for (; i < HMAC_PER_EXTENT; i++) {
		first_level_node = root->children[i];
		if (!first_level_node)
			goto out;
		for (j = 0; j < HMAC_PER_EXTENT; j++) {
			if (!first_level_node->children[j])
				goto out;
			kmem_cache_free(ecryptfs_extent_cache,
					first_level_node->children[j]->extent);
			kfree(first_level_node->children[j]);
			memset(&(first_level_node->children[j]), 0,
					sizeof(struct ecryptfs_hmac_table *));
		}
		kmem_cache_free(ecryptfs_extent_cache,
				first_level_node->extent);
		kfree(first_level_node);
		memset(&(root->children[i]), 0,
				sizeof(struct ecryptfs_hmac_table *));
	}
	ecryptfs_calculate_root_hmac(crypt_stat, crypt_stat->root->extent/*dst*/);
	ecryptfs_write_hmac_root_to_header(ecryptfs_inode, crypt_stat);
out:
	mutex_unlock(&crypt_stat->cs_hmac_mutex);
}


/**
 * ecryptfs_free_hmac_table
 * @crypt_stat: Pointer to crypt_stat struct hmac table for the  current inode
 *
 * Free all hmac extents and nodes for the hmac table
 *
 * This function should always succeed
 */
void ecryptfs_free_hmac_table(struct ecryptfs_hmac_table *root)
{
	struct ecryptfs_hmac_table *first_level_node;
	size_t i = 0;
	size_t j;

	if(!root)
		return;
	for (i = 0; i < HMAC_PER_EXTENT; i++) {
		first_level_node = root->children[i];
		if (!first_level_node)
			continue;
		for (j = 0; j < HMAC_PER_EXTENT; j++) {
			if (!first_level_node->children[j])
				continue;
			kmem_cache_free(ecryptfs_extent_cache,
					first_level_node->children[j]->extent);
			kfree(first_level_node->children[j]);
		}
		kmem_cache_free(ecryptfs_extent_cache,
				first_level_node->extent);
		kfree(first_level_node);
	}
	if (root->extent)
		kmem_cache_free(ecryptfs_extent_cache,root->extent);
	kfree(root);
}
