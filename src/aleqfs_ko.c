// SPDX-License-Identifier: GPL-2.0-only
/*
 * AleQFS — Adaptive Linux Efficient QUANTUM Filesystem (kernel driver)
 *
 * On-disk layout is shared with the userspace tools through
 * aleqfs_layout.h. Everything read from disk is treated as untrusted:
 * extents, slot counts and block numbers are validated before use so a
 * corrupt or hostile image cannot walk the kernel out of bounds.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/mutex.h>
#include <linux/highmem.h>
#include <linux/mnt_idmapping.h>
#include <linux/fs_context.h>

#include "aleqfs_layout.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
#error "aleqfs requires Linux >= 6.3 (idmap-aware VFS operations)"
#endif

#define ALEQFS_MOD_NAME  "aleqfs"
#define ALEQFS_MOD_DESC  "Adaptive Linux Efficient Quantum Filesystem"
#define ALEQFS_MOD_VER   "2.0.0"

#ifndef EFSCORRUPTED
#define EFSCORRUPTED EUCLEAN
#endif

/* ---- kernel API compatibility shims -------------------------------- */

/* v7.0 made i_state a typed struct behind accessors */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7,0,0)
#define ALEQFS_INODE_IS_NEW(inode) (inode_state_read_once(inode) & I_NEW)
#else
#define ALEQFS_INODE_IS_NEW(inode) ((inode)->i_state & I_NEW)
#endif

/* v6.15 converted ->mkdir to return the dentry (NULL == success) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,15,0)
#define ALEQFS_MKDIR_RET       struct dentry *
#define ALEQFS_MKDIR_OK        NULL
#define ALEQFS_MKRET_ERR(e)    ERR_PTR(e)
#else
#define ALEQFS_MKDIR_RET       int
#define ALEQFS_MKDIR_OK        0
#define ALEQFS_MKRET_ERR(e)    (e)
#endif

/* v6.6 introduced inode_set/get_*time accessors */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
#define ALEQFS_SET_ATIME(i, s, n) inode_set_atime(i, s, n)
#define ALEQFS_SET_MTIME(i, s, n) inode_set_mtime(i, s, n)
#define ALEQFS_SET_CTIME(i, s, n) inode_set_ctime(i, s, n)
#define ALEQFS_GET_ATIME_SEC(i)   inode_get_atime(i).tv_sec
#define ALEQFS_GET_MTIME_SEC(i)   inode_get_mtime(i).tv_sec
#define ALEQFS_GET_CTIME_SEC(i)   inode_get_ctime(i).tv_sec
#else
#define ALEQFS_SET_ATIME(i, s, n) do { (i)->i_atime.tv_sec = (s); (i)->i_atime.tv_nsec = (n); } while (0)
#define ALEQFS_SET_MTIME(i, s, n) do { (i)->i_mtime.tv_sec = (s); (i)->i_mtime.tv_nsec = (n); } while (0)
#define ALEQFS_SET_CTIME(i, s, n) do { (i)->i_ctime.tv_sec = (s); (i)->i_ctime.tv_nsec = (n); } while (0)
#define ALEQFS_GET_ATIME_SEC(i)   ((i)->i_atime.tv_sec)
#define ALEQFS_GET_MTIME_SEC(i)   ((i)->i_mtime.tv_sec)
#define ALEQFS_GET_CTIME_SEC(i)   ((i)->i_ctime.tv_sec)
#endif

/* v6.3 taught setattr_prepare about idmapping (our minimum version) */
#define aleqfs_setattr_prepare(idmap, dentry, attr) \
    setattr_prepare(idmap, dentry, attr)

#define ALEQFS_BLOCKS_TO_SECTORS(b) ((b) * (ALEQFS_BLOCK_SIZE / 512))

struct aleqfs_sb_info {
    struct aleqfs_superblock *sb;   /* lives inside sb_bh->b_data */
    struct buffer_head *sb_bh;
    struct mutex s_lock;            /* protects bitmap/inode allocation */
    unsigned long inode_table_start;
    unsigned long data_start;
    unsigned long total_blocks;
    unsigned long inode_count;
    unsigned long block_size;
};

static inline struct aleqfs_sb_info *ALEQFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

/* FNV-1a, identical to the userspace aleqfs_checksum() */
static uint64_t aleqfs_fnv1a(const void *data, size_t len)
{
    const u8 *p = data;
    uint64_t h = 0xcbf29ce484222325ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t aleqfs_grover_hash_compute(const u8 *data, size_t len)
{
    uint64_t h = 0;
    size_t i;

    for (i = 0; i < len; i++)
        h = (h ^ data[i]) * 0x9e3779b97f4a7c15ULL;
    return h;
}

/* ---- on-disk data validation ----------------------------------------- */

static inline bool aleqfs_sbi_block_ok(const struct aleqfs_sb_info *sbi,
                                       uint64_t blk)
{
    return blk >= sbi->data_start && blk < sbi->total_blocks;
}

static inline bool aleqfs_ei_extent_ok(const struct aleqfs_sb_info *sbi,
                                       const struct aleqfs_extent *e)
{
    if (e->count == 0)
        return false;
    if (e->count > (uint64_t)sbi->total_blocks)
        return false;
    return aleqfs_sbi_block_ok(sbi, e->start) &&
           e->start + e->count <= sbi->total_blocks;
}

static inline unsigned int
aleqfs_ei_extent_count(const struct aleqfs_inode *ei)
{
    return ei->extent_count > ALEQFS_NR_EXTENTS
               ? ALEQFS_NR_EXTENTS : ei->extent_count;
}

/* map a file block through validated extents; false == hole/corrupt */
static bool aleqfs_ei_find(const struct aleqfs_sb_info *sbi,
                           const struct aleqfs_inode *ei,
                           uint64_t file_block, uint64_t *dev_block)
{
    uint64_t accum = 0;
    unsigned int ec = aleqfs_ei_extent_count(ei);
    unsigned int i;

    for (i = 0; i < ec; i++) {
        const struct aleqfs_extent *e = &ei->extents[i];

        if (!aleqfs_ei_extent_ok(sbi, e))
            return false;
        if (file_block < accum + e->count) {
            *dev_block = e->start + (file_block - accum);
            return true;
        }
        accum += e->count;
    }
    return false;
}

static uint64_t aleqfs_ei_mapped(const struct aleqfs_sb_info *sbi,
                                 const struct aleqfs_inode *ei)
{
    uint64_t total = 0;
    unsigned int ec = aleqfs_ei_extent_count(ei);
    unsigned int i;

    for (i = 0; i < ec; i++) {
        if (!aleqfs_ei_extent_ok(sbi, &ei->extents[i]))
            break;
        total += ei->extents[i].count;
    }
    return total;
}

/* ---- low level block helpers ----------------------------------------- */

static int aleqfs_read_inode_block(struct super_block *sb, uint64_t ino,
                                   struct buffer_head **bhp, unsigned long *offset)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    unsigned long block;

    if (ino == 0 || ino > sbi->inode_count)
        return -EIO;

    block = sbi->inode_table_start +
            (ino - 1) / (ALEQFS_BLOCK_SIZE / ALEQFS_INODE_SIZE);
    *offset = ((ino - 1) % (ALEQFS_BLOCK_SIZE / ALEQFS_INODE_SIZE)) *
              ALEQFS_INODE_SIZE;

    if (block >= sbi->total_blocks)
        return -EIO;

    *bhp = sb_bread(sb, block);
    if (!*bhp)
        return -EIO;
    return 0;
}

/* recompute the superblock seal and mark it dirty */
static void aleqfs_super_sync(struct super_block *sb)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    if (!sbi || !sbi->sb_bh)
        return;
    sbi->sb->checksum = 0;
    sbi->sb->checksum = aleqfs_fnv1a(sbi->sb_bh->b_data, ALEQFS_BLOCK_SIZE);
    mark_buffer_dirty(sbi->sb_bh);
}

/* ---- bitmap ---------------------------------------------------------- */

static int aleqfs_bitmap_set(struct super_block *sb, uint64_t block, bool value)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    uint64_t bitmap_start = sbi->sb->bitmap_start;
    uint64_t byte_off = block / 8;
    uint64_t bit_off = block % 8;
    uint64_t buf_block;
    unsigned long buf_off;
    struct buffer_head *bh;
    uint8_t *data;

    if (block >= sbi->total_blocks)
        return -EINVAL;
    if (byte_off >= (uint64_t)ALEQFS_BITMAP_BLOCKS * ALEQFS_BLOCK_SIZE)
        return -EINVAL;

    buf_block = bitmap_start + byte_off / ALEQFS_BLOCK_SIZE;
    buf_off = byte_off % ALEQFS_BLOCK_SIZE;

    bh = sb_bread(sb, buf_block);
    if (!bh)
        return -EIO;

    data = (uint8_t *)bh->b_data;
    if (value)
        data[buf_off] |= (1 << bit_off);
    else
        data[buf_off] &= ~(1 << bit_off);

    mark_buffer_dirty(bh);
    brelse(bh);
    return 0;
}

static bool aleqfs_bitmap_test(struct super_block *sb, uint64_t block)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    uint64_t bitmap_start = sbi->sb->bitmap_start;
    uint64_t byte_off = block / 8;
    uint64_t bit_off = block % 8;
    uint64_t buf_block;
    unsigned long buf_off;
    struct buffer_head *bh;
    bool used = true;

    if (block >= sbi->total_blocks)
        return true;
    if (byte_off >= (uint64_t)ALEQFS_BITMAP_BLOCKS * ALEQFS_BLOCK_SIZE)
        return true;

    buf_block = bitmap_start + byte_off / ALEQFS_BLOCK_SIZE;
    buf_off = byte_off % ALEQFS_BLOCK_SIZE;

    bh = sb_bread(sb, buf_block);
    if (!bh)
        return true;
    used = (((uint8_t *)bh->b_data)[buf_off] & (1 << bit_off)) != 0;
    brelse(bh);
    return used;
}

static int aleqfs_bitmap_alloc(struct super_block *sb, uint64_t *block)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    uint64_t i;

    mutex_lock(&sbi->s_lock);
    for (i = sbi->data_start; i < sbi->total_blocks; i++) {
        if (!aleqfs_bitmap_test(sb, i)) {
            aleqfs_bitmap_set(sb, i, true);
            if (sbi->sb->free_blocks > 0)
                sbi->sb->free_blocks--;
            aleqfs_super_sync(sb);
            *block = i;
            mutex_unlock(&sbi->s_lock);
            return 0;
        }
    }
    mutex_unlock(&sbi->s_lock);
    return -ENOSPC;
}

/* test-and-set: used to grow the last extent when physically adjacent */
static bool aleqfs_bitmap_reserve(struct super_block *sb, uint64_t block)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    bool ok = false;

    mutex_lock(&sbi->s_lock);
    if (aleqfs_sbi_block_ok(sbi, block) && !aleqfs_bitmap_test(sb, block)) {
        aleqfs_bitmap_set(sb, block, true);
        if (sbi->sb->free_blocks > 0)
            sbi->sb->free_blocks--;
        aleqfs_super_sync(sb);
        ok = true;
    }
    mutex_unlock(&sbi->s_lock);
    return ok;
}

static void aleqfs_bitmap_release(struct super_block *sb, uint64_t block)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    mutex_lock(&sbi->s_lock);
    if (aleqfs_sbi_block_ok(sbi, block) && aleqfs_bitmap_test(sb, block)) {
        aleqfs_bitmap_set(sb, block, false);
        sbi->sb->free_blocks++;
        aleqfs_super_sync(sb);
    }
    mutex_unlock(&sbi->s_lock);
}

/* ---- inode allocation ------------------------------------------------ */

static int aleqfs_inode_alloc(struct super_block *sb, uint64_t *ino)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    uint64_t i;

    mutex_lock(&sbi->s_lock);
    for (i = ALEQFS_ROOT_INO; i <= sbi->inode_count; i++) {
        struct buffer_head *bh;
        unsigned long offset;
        struct aleqfs_inode *ei;

        if (aleqfs_read_inode_block(sb, i, &bh, &offset))
            continue;

        ei = (struct aleqfs_inode *)(bh->b_data + offset);
        if (ei->mode == 0) {
            memset(ei, 0, sizeof(*ei));
            ei->amplitude.real = 32767;
            mark_buffer_dirty(bh);
            brelse(bh);
            *ino = i;
            if (sbi->sb->free_inodes > 0)
                sbi->sb->free_inodes--;
            aleqfs_super_sync(sb);
            mutex_unlock(&sbi->s_lock);
            return 0;
        }
        brelse(bh);
    }
    mutex_unlock(&sbi->s_lock);
    return -ENOSPC;
}

/* zero the on-disk inode and return it to the free pool */
static void aleqfs_inode_release(struct super_block *sb, uint64_t ino)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *bh;
    unsigned long offset;

    if (aleqfs_read_inode_block(sb, ino, &bh, &offset))
        return;
    memset(bh->b_data + offset, 0, ALEQFS_INODE_SIZE);
    mark_buffer_dirty(bh);
    brelse(bh);

    mutex_lock(&sbi->s_lock);
    if (sbi->sb->free_inodes < sbi->inode_count)
        sbi->sb->free_inodes++;
    aleqfs_super_sync(sb);
    mutex_unlock(&sbi->s_lock);
}

static int aleqfs_inode_dirty(struct super_block *sb, uint64_t ino,
                              const struct aleqfs_inode *inode)
{
    struct buffer_head *bh;
    unsigned long offset;
    int ret = aleqfs_read_inode_block(sb, ino, &bh, &offset);

    if (ret)
        return ret;
    memcpy(bh->b_data + offset, inode, sizeof(*inode));
    mark_buffer_dirty(bh);
    brelse(bh);
    return 0;
}

/* ---- directory blocks ------------------------------------------------ */

static unsigned int aleqfs_dentry_size(unsigned int name_len)
{
    return sizeof(struct aleqfs_direntry) + name_len;
}

static int aleqfs_dir_find_in_bh(struct buffer_head *bh,
                                 const unsigned char *name,
                                 unsigned int name_len)
{
    unsigned int off = 0;

    while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
        struct aleqfs_direntry *de = (struct aleqfs_direntry *)(bh->b_data + off);
        unsigned int sz;

        if (de->name_len == 0)
            return -ENOENT;
        sz = aleqfs_dentry_size(de->name_len);
        if (off + sz > ALEQFS_BLOCK_SIZE)
            break;
        if (de->name_len == name_len &&
            memcmp(de->name, name, name_len) == 0)
            return (int)off;
        off += sz;
    }
    return -ENOSPC;
}

static unsigned int aleqfs_dir_end_in_bh(struct buffer_head *bh)
{
    unsigned int off = 0;

    while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
        struct aleqfs_direntry *de = (struct aleqfs_direntry *)(bh->b_data + off);
        unsigned int sz;

        if (de->name_len == 0)
            return off;
        sz = aleqfs_dentry_size(de->name_len);
        if (off + sz > ALEQFS_BLOCK_SIZE)
            return ALEQFS_BLOCK_SIZE;
        off += sz;
    }
    return ALEQFS_BLOCK_SIZE;
}

/*
 * Entries stay packed: removing one compacts the rest of the block
 * forward. A zero-length tombstone in the middle would hide every entry
 * after it from lookup/readdir.
 */
static void aleqfs_dir_compact_entry(struct buffer_head *bh,
                                     unsigned int off, unsigned int sz)
{
    unsigned int end = aleqfs_dir_end_in_bh(bh);
    uint8_t *data = (uint8_t *)bh->b_data;

    if (end >= off + sz && end <= ALEQFS_BLOCK_SIZE) {
        memmove(data + off, data + off + sz, end - (off + sz));
        memset(data + end - sz, 0, sz);
    } else {
        memset(data + off, 0, sz);
    }
}

static int aleqfs_dir_add_entry(struct super_block *sb, uint64_t dir_ino,
                                uint64_t child_ino, const unsigned char *name,
                                unsigned int name_len)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *dir_bh;
    unsigned long dir_off;
    struct aleqfs_inode *dir_ei;
    unsigned int esize = aleqfs_dentry_size(name_len);
    unsigned int ec;
    unsigned int e;
    int ret;

    if (name_len == 0 || name_len > ALEQFS_MAX_NAME)
        return -EINVAL;

    ret = aleqfs_read_inode_block(sb, dir_ino, &dir_bh, &dir_off);
    if (ret)
        return ret;
    dir_ei = (struct aleqfs_inode *)(dir_bh->b_data + dir_off);

    ec = aleqfs_ei_extent_count(dir_ei);
    for (e = 0; e < ec; e++) {
        uint64_t start = dir_ei->extents[e].start;
        uint64_t count = dir_ei->extents[e].count;
        uint64_t b;

        if (!aleqfs_ei_extent_ok(sbi, &dir_ei->extents[e]))
            continue;

        for (b = 0; b < count; b++) {
            struct buffer_head *bh = sb_bread(sb, start + b);
            int found;
            unsigned int end;

            if (!bh)
                continue;

            found = aleqfs_dir_find_in_bh(bh, name, name_len);
            if (found >= 0) {
                struct aleqfs_direntry *de =
                    (struct aleqfs_direntry *)(bh->b_data + found);
                de->ino = child_ino;
                de->amplitude_real = 32767;
                de->amplitude_imag = 0;
                mark_buffer_dirty(bh);
                brelse(bh);
                brelse(dir_bh);
                return 0;
            }

            end = aleqfs_dir_end_in_bh(bh);
            if (end + esize <= ALEQFS_BLOCK_SIZE) {
                struct aleqfs_direntry *de =
                    (struct aleqfs_direntry *)(bh->b_data + end);
                de->ino = child_ino;
                de->name_len = (uint8_t)name_len;
                de->amplitude_real = 32767;
                de->amplitude_imag = 0;
                memcpy(de->name, name, name_len);
                mark_buffer_dirty(bh);
                brelse(bh);
                brelse(dir_bh);
                return 0;
            }
            brelse(bh);
        }
    }

    /* no room in existing blocks: check the extent list before allocating */
    if (dir_ei->extent_count >= ALEQFS_NR_EXTENTS) {
        struct aleqfs_extent *last =
            &dir_ei->extents[aleqfs_ei_extent_count(dir_ei) - 1];

        if (!(aleqfs_ei_extent_ok(sbi, last) &&
              last->start + last->count < sbi->total_blocks)) {
            brelse(dir_bh);
            return -ENOSPC;
        }
    }

    {
        uint64_t new_block;
        struct buffer_head *nbh;

        ret = aleqfs_bitmap_alloc(sb, &new_block);
        if (ret) {
            brelse(dir_bh);
            return ret;
        }

        nbh = sb_bread(sb, new_block);
        if (!nbh) {
            aleqfs_bitmap_release(sb, new_block);
            brelse(dir_bh);
            return -EIO;
        }
        memset(nbh->b_data, 0, ALEQFS_BLOCK_SIZE);

        {
            struct aleqfs_direntry *de = (struct aleqfs_direntry *)nbh->b_data;
            de->ino = child_ino;
            de->name_len = (uint8_t)name_len;
            de->amplitude_real = 32767;
            de->amplitude_imag = 0;
            memcpy(de->name, name, name_len);
        }
        mark_buffer_dirty(nbh);
        brelse(nbh);

        if (dir_ei->extent_count > 0) {
            unsigned int ecount = aleqfs_ei_extent_count(dir_ei);
            struct aleqfs_extent *last = &dir_ei->extents[ecount - 1];
            if (aleqfs_ei_extent_ok(sbi, last) &&
                last->start + last->count == new_block) {
                last->count++;
            } else if (dir_ei->extent_count < ALEQFS_NR_EXTENTS) {
                dir_ei->extents[dir_ei->extent_count].start = new_block;
                dir_ei->extents[dir_ei->extent_count].count = 1;
                dir_ei->extent_count++;
            } else {
                aleqfs_bitmap_release(sb, new_block);
                brelse(dir_bh);
                return -ENOSPC;
            }
        } else {
            dir_ei->extents[0].start = new_block;
            dir_ei->extents[0].count = 1;
            dir_ei->extent_count = 1;
        }
        dir_ei->blocks = aleqfs_ei_mapped(sbi, dir_ei);
    }

    mark_buffer_dirty(dir_bh);
    brelse(dir_bh);
    return 0;
}

static int aleqfs_dir_remove_entry(struct super_block *sb, uint64_t dir_ino,
                                   const unsigned char *name,
                                   unsigned int name_len)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *dir_bh;
    unsigned long dir_off;
    struct aleqfs_inode *dir_ei;
    struct aleqfs_extent extents[ALEQFS_NR_EXTENTS];
    unsigned int ec;
    unsigned int e;
    int ret;

    ret = aleqfs_read_inode_block(sb, dir_ino, &dir_bh, &dir_off);
    if (ret)
        return ret;
    dir_ei = (struct aleqfs_inode *)(dir_bh->b_data + dir_off);

    /* snapshot the validated extents, then work off the dir buffer */
    ec = aleqfs_ei_extent_count(dir_ei);
    memset(extents, 0, sizeof(extents));
    for (e = 0; e < ec; e++) {
        if (!aleqfs_ei_extent_ok(sbi, &dir_ei->extents[e])) {
            ec = e;
            break;
        }
        extents[e] = dir_ei->extents[e];
    }

    for (e = 0; e < ec; e++) {
        uint64_t b;

        for (b = 0; b < extents[e].count; b++) {
            struct buffer_head *bh = sb_bread(sb, extents[e].start + b);
            int found;

            if (!bh)
                continue;

            found = aleqfs_dir_find_in_bh(bh, name, name_len);
            if (found >= 0) {
                unsigned int sz = aleqfs_dentry_size(
                    ((struct aleqfs_direntry *)(bh->b_data + found))->name_len);
                aleqfs_dir_compact_entry(bh, (unsigned int)found, sz);
                mark_buffer_dirty(bh);
                brelse(bh);
                dir_ei->mtime = ktime_get_real_seconds();
                mark_buffer_dirty(dir_bh);
                brelse(dir_bh);
                return 0;
            }
            brelse(bh);
        }
    }

    brelse(dir_bh);
    return -ENOENT;
}

static uint64_t aleqfs_dir_lookup(struct super_block *sb, uint64_t dir_ino,
                                  const unsigned char *name,
                                  unsigned int name_len)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *dir_bh;
    unsigned long dir_off;
    struct aleqfs_inode *dir_ei;
    struct aleqfs_extent extents[ALEQFS_NR_EXTENTS];
    unsigned int ec;
    unsigned int e;
    uint64_t result = 0;

    if (name_len == 0 || name_len > ALEQFS_MAX_NAME)
        return 0;

    if (aleqfs_read_inode_block(sb, dir_ino, &dir_bh, &dir_off))
        return 0;
    dir_ei = (struct aleqfs_inode *)(dir_bh->b_data + dir_off);

    ec = aleqfs_ei_extent_count(dir_ei);
    memset(extents, 0, sizeof(extents));
    for (e = 0; e < ec; e++) {
        if (!aleqfs_ei_extent_ok(sbi, &dir_ei->extents[e])) {
            ec = e;
            break;
        }
        extents[e] = dir_ei->extents[e];
    }
    brelse(dir_bh);

    for (e = 0; e < ec && result == 0; e++) {
        uint64_t b;

        for (b = 0; b < extents[e].count; b++) {
            struct buffer_head *bh = sb_bread(sb, extents[e].start + b);
            int found;

            if (!bh)
                continue;
            found = aleqfs_dir_find_in_bh(bh, name, name_len);
            if (found >= 0) {
                /* read the ino before releasing the buffer */
                result = ((struct aleqfs_direntry *)(bh->b_data + found))->ino;
                brelse(bh);
                break;
            }
            brelse(bh);
        }
    }
    return result;
}

static bool aleqfs_dir_empty(struct super_block *sb, uint64_t dir_ino)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *dir_bh;
    unsigned long dir_off;
    struct aleqfs_inode *dir_ei;
    struct aleqfs_extent extents[ALEQFS_NR_EXTENTS];
    unsigned int ec;
    unsigned int e;
    bool empty = true;

    if (aleqfs_read_inode_block(sb, dir_ino, &dir_bh, &dir_off))
        return false;
    dir_ei = (struct aleqfs_inode *)(dir_bh->b_data + dir_off);

    ec = aleqfs_ei_extent_count(dir_ei);
    memset(extents, 0, sizeof(extents));
    for (e = 0; e < ec; e++) {
        if (!aleqfs_ei_extent_ok(sbi, &dir_ei->extents[e])) {
            ec = e;
            break;
        }
        extents[e] = dir_ei->extents[e];
    }
    brelse(dir_bh);

    for (e = 0; e < ec && empty; e++) {
        uint64_t b;

        for (b = 0; b < extents[e].count; b++) {
            struct buffer_head *bh = sb_bread(sb, extents[e].start + b);

            if (!bh)
                continue;
            if (aleqfs_dir_end_in_bh(bh) != 0)
                empty = false;
            brelse(bh);
            if (!empty)
                break;
        }
    }
    return empty;
}

/* ---- inode <-> VFS ---------------------------------------------------- */

static int aleqfs_read_inode(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *bh;
    unsigned long offset;
    struct aleqfs_inode *ei;
    uint64_t ino = inode->i_ino;
    int ret;

    ret = aleqfs_read_inode_block(sb, ino, &bh, &offset);
    if (ret)
        return ret;

    ei = (struct aleqfs_inode *)(bh->b_data + offset);

    if (ei->mode == 0) {
        brelse(bh);
        return -ENOENT;
    }
    /* a file can never be bigger than the whole image */
    if (ei->size > (uint64_t)sbi->total_blocks * ALEQFS_BLOCK_SIZE) {
        brelse(bh);
        return -EFSCORRUPTED;
    }

    inode->i_mode   = ei->mode;
    inode->i_uid.val = ei->uid;
    inode->i_gid.val = ei->gid;
    inode->i_size   = ei->size;
    inode->i_blocks = ALEQFS_BLOCKS_TO_SECTORS(ei->blocks);
    ALEQFS_SET_ATIME(inode, ei->atime, 0);
    ALEQFS_SET_MTIME(inode, ei->mtime, 0);
    ALEQFS_SET_CTIME(inode, ei->ctime, 0);
    set_nlink(inode, ei->links);

    brelse(bh);
    return 0;
}

static int aleqfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh;
    unsigned long offset;
    struct aleqfs_inode *ei;
    uint64_t ino = inode->i_ino;
    int ret;

    ret = aleqfs_read_inode_block(sb, ino, &bh, &offset);
    if (ret)
        return ret;

    ei = (struct aleqfs_inode *)(bh->b_data + offset);

    ei->mode   = inode->i_mode;
    ei->uid    = (uint16_t)from_kuid(&init_user_ns, inode->i_uid);
    ei->gid    = (uint16_t)from_kgid(&init_user_ns, inode->i_gid);
    ei->size   = inode->i_size;
    ei->blocks = inode->i_blocks / (ALEQFS_BLOCK_SIZE / 512);
    ei->atime  = ALEQFS_GET_ATIME_SEC(inode);
    ei->mtime  = ALEQFS_GET_MTIME_SEC(inode);
    ei->ctime  = ALEQFS_GET_CTIME_SEC(inode);
    ei->links  = inode->i_nlink;

    mark_buffer_dirty(bh);
    brelse(bh);
    return 0;
}

/* free every data block of a disk inode and release the inode slot */
static void aleqfs_free_disk_inode(struct super_block *sb, uint64_t ino)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *bh;
    unsigned long offset;
    struct aleqfs_inode *ei;
    unsigned int ec;
    unsigned int i;

    if (aleqfs_read_inode_block(sb, ino, &bh, &offset))
        return;
    ei = (struct aleqfs_inode *)(bh->b_data + offset);

    ec = aleqfs_ei_extent_count(ei);
    for (i = 0; i < ec; i++) {
        uint64_t b;

        if (!aleqfs_ei_extent_ok(sbi, &ei->extents[i]))
            continue;
        for (b = 0; b < ei->extents[i].count; b++)
            aleqfs_bitmap_release(sb, ei->extents[i].start + b);
    }

    memset(bh->b_data + offset, 0, ALEQFS_INODE_SIZE);
    mark_buffer_dirty(bh);
    brelse(bh);

    mutex_lock(&sbi->s_lock);
    if (sbi->sb->free_inodes < sbi->inode_count)
        sbi->sb->free_inodes++;
    aleqfs_super_sync(sb);
    mutex_unlock(&sbi->s_lock);
}

static void aleqfs_evict_inode(struct inode *inode)
{
    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);

    if (inode->i_nlink)
        return;

    aleqfs_free_disk_inode(inode->i_sb, inode->i_ino);
}

/* seal the first data block for the userspace decoherence check */
static void aleqfs_seal_inode(struct super_block *sb, struct aleqfs_inode *ei)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *bh;

    if (ei->size == 0 || aleqfs_ei_extent_count(ei) == 0 ||
        !aleqfs_ei_extent_ok(sbi, &ei->extents[0])) {
        ei->decoherence_stamp = 0;
        return;
    }

    bh = sb_bread(sb, ei->extents[0].start);
    if (!bh)
        return;
    ei->decoherence_stamp = aleqfs_fnv1a(bh->b_data, ALEQFS_BLOCK_SIZE);
    brelse(bh);
}

/* ---- file operations -------------------------------------------------- */

static int aleqfs_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int aleqfs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t aleqfs_read(struct file *file, char __user *buf,
                           size_t len, loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    loff_t pos = *ppos;
    ssize_t ret = 0;

    if (pos < 0)
        return -EINVAL;
    if (pos >= i_size_read(inode))
        return 0;
    if (len > (size_t)(i_size_read(inode) - pos))
        len = (size_t)(i_size_read(inode) - pos);

    while (len > 0) {
        uint64_t block_off = pos / ALEQFS_BLOCK_SIZE;
        uint64_t byte_off = pos % ALEQFS_BLOCK_SIZE;
        struct buffer_head *inode_bh;
        unsigned long io;
        struct aleqfs_inode *ei;
        uint64_t dev_block = 0;
        bool mapped;
        size_t to_copy = ALEQFS_BLOCK_SIZE - byte_off;

        if (to_copy > len)
            to_copy = len;

        if (aleqfs_read_inode_block(sb, inode->i_ino, &inode_bh, &io))
            return ret ? ret : -EIO;
        ei = (struct aleqfs_inode *)(inode_bh->b_data + io);
        mapped = aleqfs_ei_find(sbi, ei, block_off, &dev_block);
        brelse(inode_bh);

        if (mapped && !aleqfs_sbi_block_ok(sbi, dev_block))
            return ret ? ret : -EFSCORRUPTED;

        if (!mapped) {
            /* hole inside i_size: read as zeros */
            void *zp;
            int c;

            zp = kmap_local_page(ZERO_PAGE(0));
            c = copy_to_user(buf, (char *)zp + byte_off, to_copy);
            kunmap_local(zp);
            if (c)
                return ret ? ret : -EFAULT;
        } else {
            struct buffer_head *bh = sb_bread(sb, dev_block);

            if (!bh)
                return ret ? ret : -EIO;
            if (copy_to_user(buf, bh->b_data + byte_off, to_copy)) {
                brelse(bh);
                return ret ? ret : -EFAULT;
            }
            brelse(bh);
        }

        buf += to_copy;
        pos += to_copy;
        ret += to_copy;
        len -= to_copy;
    }

    *ppos = pos;
    return ret;
}

/* append one block to the disk inode mapping (extent growth or new extent) */
static int aleqfs_ei_append_block(struct super_block *sb,
                                  struct aleqfs_inode *ei, uint64_t *blk)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    unsigned int ec = aleqfs_ei_extent_count(ei);

    if (ec > 0 && aleqfs_ei_extent_ok(sbi, &ei->extents[ec - 1])) {
        struct aleqfs_extent *last = &ei->extents[ec - 1];
        uint64_t next = last->start + last->count;

        if (next < sbi->total_blocks && aleqfs_bitmap_reserve(sb, next)) {
            last->count++;
            ei->blocks++;
            *blk = next;
            return 0;
        }
    }

    if (ei->extent_count >= ALEQFS_NR_EXTENTS)
        return -ENOSPC;

    {
        uint64_t nb;
        int ret = aleqfs_bitmap_alloc(sb, &nb);

        if (ret)
            return ret;
        ei->extents[ei->extent_count].start = nb;
        ei->extents[ei->extent_count].count = 1;
        ei->extent_count++;
        ei->blocks++;
        *blk = nb;
        return 0;
    }
}

/*
 * Ensure file blocks [0..block_off] are all mapped, zero-filling holes so
 * the extents keep describing a contiguous file-block range.
 */
static int aleqfs_ei_grow(struct super_block *sb, struct aleqfs_inode *ei,
                          uint64_t block_off, uint64_t *dev_block,
                          bool *fresh)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    *fresh = false;

    for (;;) {
        uint64_t mapped = aleqfs_ei_mapped(sbi, ei);
        uint64_t nb;
        int ret;

        if (mapped > block_off) {
            if (aleqfs_ei_find(sbi, ei, block_off, dev_block) &&
                aleqfs_sbi_block_ok(sbi, *dev_block))
                return 0;
            return -EFSCORRUPTED;
        }

        ret = aleqfs_ei_append_block(sb, ei, &nb);
        if (ret)
            return ret;

        if (mapped < block_off) {
            struct buffer_head *zbh = sb_bread(sb, nb);

            if (!zbh)
                return -EIO;
            memset(zbh->b_data, 0, ALEQFS_BLOCK_SIZE);
            mark_buffer_dirty(zbh);
            brelse(zbh);
        } else {
            *dev_block = nb;
            *fresh = true;
            return 0;
        }
    }
}

static ssize_t aleqfs_write(struct file *file, const char __user *buf,
                            size_t len, loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct super_block *sb = inode->i_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    loff_t pos = *ppos;
    ssize_t written = 0;
    uint64_t grover_hash = 0;
    int err = 0;

    if (pos < 0)
        return -EINVAL;
    if (len == 0)
        return 0;

    inode_lock(inode);

    while (len > 0) {
        uint64_t block_off = pos / ALEQFS_BLOCK_SIZE;
        uint64_t byte_off = pos % ALEQFS_BLOCK_SIZE;
        size_t to_write = ALEQFS_BLOCK_SIZE - byte_off;
        struct buffer_head *inode_bh;
        unsigned long io;
        struct aleqfs_inode *ei;
        uint64_t dev_block = 0;
        bool fresh = false;

        if (to_write > len)
            to_write = len;

        if (aleqfs_read_inode_block(sb, inode->i_ino, &inode_bh, &io)) {
            err = -EIO;
            break;
        }
        ei = (struct aleqfs_inode *)(inode_bh->b_data + io);

        if (!aleqfs_ei_find(sbi, ei, block_off, &dev_block)) {
            err = aleqfs_ei_grow(sb, ei, block_off, &dev_block, &fresh);
            if (err) {
                brelse(inode_bh);
                break;
            }
            mark_buffer_dirty(inode_bh);
        } else if (!aleqfs_sbi_block_ok(sbi, dev_block)) {
            brelse(inode_bh);
            err = -EFSCORRUPTED;
            break;
        }
        brelse(inode_bh);

        {
            struct buffer_head *data_bh = sb_bread(sb, dev_block);

            if (!data_bh) {
                err = -EIO;
                break;
            }
            if (fresh && (byte_off != 0 || to_write != ALEQFS_BLOCK_SIZE))
                memset(data_bh->b_data, 0, ALEQFS_BLOCK_SIZE);
            if (copy_from_user(data_bh->b_data + byte_off, buf, to_write)) {
                brelse(data_bh);
                err = -EFAULT;
                break;
            }
            mark_buffer_dirty(data_bh);

            grover_hash ^= aleqfs_grover_hash_compute(
                (const u8 *)data_bh->b_data + byte_off, to_write);
            brelse(data_bh);
        }

        buf += to_write;
        pos += to_write;
        written += to_write;
        len -= to_write;
    }

    if (written > 0) {
        struct timespec64 now = current_time(inode);
        loff_t newsize = max_t(loff_t, i_size_read(inode), pos);
        struct buffer_head *ibh;
        unsigned long ioff;

        *ppos = pos;
        i_size_write(inode, newsize);
        inode->i_blocks = (newsize + 511) / 512;
        ALEQFS_SET_MTIME(inode, now.tv_sec, now.tv_nsec);
        ALEQFS_SET_CTIME(inode, now.tv_sec, now.tv_nsec);
        mark_inode_dirty(inode);

        if (!aleqfs_read_inode_block(sb, inode->i_ino, &ibh, &ioff)) {
            struct aleqfs_inode *ei = (struct aleqfs_inode *)(ibh->b_data + ioff);

            ei->size = newsize;
            ei->blocks = aleqfs_ei_mapped(sbi, ei);
            ei->grover_hash = grover_hash;
            ei->mtime = now.tv_sec;
            aleqfs_seal_inode(sb, ei);
            mark_buffer_dirty(ibh);
            brelse(ibh);
        }
    }

    inode_unlock(inode);

    if (written)
        return written;
    return err ? err : -ENOSPC;
}

static void aleqfs_do_truncate(struct inode *inode)
{
    struct super_block *sb = inode->i_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    uint64_t keep_blocks = (i_size_read(inode) + ALEQFS_BLOCK_SIZE - 1) /
                           ALEQFS_BLOCK_SIZE;
    struct buffer_head *bh;
    unsigned long offset;
    struct aleqfs_inode *ei;
    unsigned int ec;
    unsigned int i;
    uint64_t accum = 0;

    if (aleqfs_read_inode_block(sb, inode->i_ino, &bh, &offset))
        return;
    ei = (struct aleqfs_inode *)(bh->b_data + offset);

    ec = aleqfs_ei_extent_count(ei);
    for (i = 0; i < ec; i++) {
        struct aleqfs_extent *e = &ei->extents[i];
        uint64_t b;

        if (!aleqfs_ei_extent_ok(sbi, e))
            continue;

        if (accum >= keep_blocks) {
            for (b = 0; b < e->count; b++)
                aleqfs_bitmap_release(sb, e->start + b);
            ei->extent_count = i;
            break;
        }
        if (accum + e->count > keep_blocks) {
            uint64_t tail = accum + e->count - keep_blocks;

            for (b = e->count - tail; b < e->count; b++)
                aleqfs_bitmap_release(sb, e->start + b);
            e->count -= tail;
            accum = keep_blocks;
            continue;
        }
        accum += e->count;
    }

    /* zero the tail of the last kept block so a later append cannot
     * resurrect deleted bytes */
    if (keep_blocks > 0 && (i_size_read(inode) % ALEQFS_BLOCK_SIZE)) {
        uint64_t last_blk;

        if (aleqfs_ei_find(sbi, ei, keep_blocks - 1, &last_blk) &&
            aleqfs_sbi_block_ok(sbi, last_blk)) {
            struct buffer_head *zbh = sb_bread(sb, last_blk);

            if (zbh) {
                memset(zbh->b_data + (i_size_read(inode) % ALEQFS_BLOCK_SIZE),
                       0,
                       ALEQFS_BLOCK_SIZE -
                           (i_size_read(inode) % ALEQFS_BLOCK_SIZE));
                mark_buffer_dirty(zbh);
                brelse(zbh);
            }
        }
    }

    ei->size = i_size_read(inode);
    ei->blocks = aleqfs_ei_mapped(sbi, ei);
    aleqfs_seal_inode(sb, ei);
    mark_buffer_dirty(bh);
    brelse(bh);
}

static int aleqfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                          struct iattr *attr)
{
    struct inode *inode = d_inode(dentry);
    int error;

    error = aleqfs_setattr_prepare(idmap, dentry, attr);
    if (error)
        return error;

    if ((attr->ia_valid & ATTR_SIZE) &&
        attr->ia_size != i_size_read(inode)) {
        error = inode_newsize_ok(inode, attr->ia_size);
        if (error)
            return error;
        truncate_setsize(inode, attr->ia_size);
        aleqfs_do_truncate(inode);
    }

    setattr_copy(idmap, inode, attr);
    mark_inode_dirty(inode);
    return 0;
}

static int aleqfs_getattr(struct mnt_idmap *idmap,
                          const struct path *path, struct kstat *stat,
                          u32 request_mask, unsigned int flags)
{
    struct inode *inode = d_inode(path->dentry);

    generic_fillattr(idmap, request_mask, inode, stat);
    return 0;
}

static const struct file_operations aleqfs_file_ops = {
    .owner   = THIS_MODULE,
    .open    = aleqfs_open,
    .release = aleqfs_release,
    .read    = aleqfs_read,
    .write   = aleqfs_write,
    .llseek  = generic_file_llseek,
};

/* ---- directory operations --------------------------------------------- */

static const struct inode_operations aleqfs_dir_inode_ops;
static const struct file_operations aleqfs_dir_ops;
static const struct inode_operations aleqfs_inode_ops;

static struct inode *aleqfs_iget(struct super_block *sb, uint64_t ino)
{
    struct inode *inode;
    int ret;

    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(ALEQFS_INODE_IS_NEW(inode)))
        return inode;

    ret = aleqfs_read_inode(inode);
    if (ret) {
        iget_failed(inode);
        return ERR_PTR(ret);
    }

    if (S_ISDIR(inode->i_mode)) {
        inode->i_op = &aleqfs_dir_inode_ops;
        inode->i_fop = &aleqfs_dir_ops;
    } else {
        inode->i_op = &aleqfs_inode_ops;
        inode->i_fop = &aleqfs_file_ops;
    }
    unlock_new_inode(inode);
    return inode;
}

static struct dentry *aleqfs_lookup(struct inode *dir, struct dentry *dentry,
                                    unsigned int flags)
{
    struct super_block *sb = dir->i_sb;
    const unsigned char *name = dentry->d_name.name;
    unsigned int name_len = dentry->d_name.len;
    uint64_t child_ino;
    struct inode *child;

    if (name_len > ALEQFS_MAX_NAME)
        return ERR_PTR(-ENAMETOOLONG);

    child_ino = aleqfs_dir_lookup(sb, dir->i_ino, name, name_len);
    if (!child_ino) {
        d_add(dentry, NULL);
        return NULL;
    }

    child = aleqfs_iget(sb, child_ino);
    if (IS_ERR(child))
        return ERR_CAST(child);

    return d_splice_alias(child, dentry);
}

static int aleqfs_iterate(struct file *file, struct dir_context *ctx)
{
    struct inode *dir = file_inode(file);
    struct super_block *sb = dir->i_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);
    struct buffer_head *dir_bh;
    unsigned long dir_off;
    struct aleqfs_inode *dir_ei;
    struct aleqfs_extent dir_extents[ALEQFS_NR_EXTENTS];
    unsigned int dir_extent_count;
    unsigned int e;
    unsigned long long entry_idx = 1;

    if (ctx->pos == 0) {
        if (!dir_emit_dots(file, ctx))
            return 0;
        /* dir_emit_dots leaves ctx->pos at 2 */
    }

    if (aleqfs_read_inode_block(sb, dir->i_ino, &dir_bh, &dir_off))
        return -EIO;
    dir_ei = (struct aleqfs_inode *)(dir_bh->b_data + dir_off);

    dir_extent_count = aleqfs_ei_extent_count(dir_ei);
    memset(dir_extents, 0, sizeof(dir_extents));
    for (e = 0; e < dir_extent_count; e++) {
        if (!aleqfs_ei_extent_ok(sbi, &dir_ei->extents[e])) {
            dir_extent_count = e;
            break;
        }
        dir_extents[e] = dir_ei->extents[e];
    }
    brelse(dir_bh);

    for (e = 0; e < dir_extent_count; e++) {
        uint64_t start = dir_extents[e].start;
        uint64_t count = dir_extents[e].count;
        uint64_t b;

        for (b = 0; b < count; b++) {
            struct buffer_head *bh = sb_bread(sb, start + b);
            unsigned int off = 0;

            if (!bh)
                continue;

            while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
                struct aleqfs_direntry *de =
                    (struct aleqfs_direntry *)(bh->b_data + off);
                unsigned int sz;

                if (de->name_len == 0)
                    break;
                sz = aleqfs_dentry_size(de->name_len);
                if (off + sz > ALEQFS_BLOCK_SIZE)
                    break;

                if ((unsigned long long)(entry_idx + 1) >= ctx->pos) {
                    umode_t dtype = DT_UNKNOWN;
                    struct inode *child = ilookup(sb, de->ino);

                    if (child) {
                        dtype = fs_umode_to_dtype(child->i_mode);
                        iput(child);
                    }

                    if (!dir_emit(ctx, (const char *)de->name,
                                  de->name_len, de->ino, dtype)) {
                        brelse(bh);
                        return 0;
                    }
                    ctx->pos = entry_idx + 2;
                }
                entry_idx++;
                off += sz;
            }
            brelse(bh);
        }
    }
    return 0;
}

static void aleqfs_init_disk_inode(struct aleqfs_inode *ei, umode_t mode,
                                   uint16_t links)
{
    time64_t now = ktime_get_real_seconds();

    memset(ei, 0, sizeof(*ei));
    ei->mode  = mode;
    ei->uid   = (uint16_t)from_kuid(&init_user_ns, current_fsuid());
    ei->gid   = (uint16_t)from_kgid(&init_user_ns, current_fsgid());
    ei->links = links;
    ei->atime = now;
    ei->mtime = now;
    ei->ctime = now;
    ei->amplitude.real = 32767;
    ei->amplitude.imag = 0;
}

static ALEQFS_MKDIR_RET aleqfs_mkdir(struct mnt_idmap *idmap,
                                     struct inode *dir,
                                     struct dentry *dentry, umode_t mode)
{
    struct super_block *sb = dir->i_sb;
    struct aleqfs_inode ei;
    struct inode *child;
    uint64_t ino;
    int err;

    err = aleqfs_inode_alloc(sb, &ino);
    if (err)
        return ALEQFS_MKRET_ERR(err);

    aleqfs_init_disk_inode(&ei, S_IFDIR | (mode & 07777), 2);
    ei.decoherence_stamp = ktime_get_real_seconds();

    err = aleqfs_inode_dirty(sb, ino, &ei);
    if (err)
        goto out_release;

    err = aleqfs_dir_add_entry(sb, dir->i_ino, ino,
                               (const unsigned char *)dentry->d_name.name,
                               dentry->d_name.len);
    if (err)
        goto out_release;

    child = aleqfs_iget(sb, ino);
    if (IS_ERR(child)) {
        err = PTR_ERR(child);
        aleqfs_dir_remove_entry(sb, dir->i_ino,
                                (const unsigned char *)dentry->d_name.name,
                                dentry->d_name.len);
        goto out_release;
    }

    inode_inc_link_count(dir);
    mark_inode_dirty(dir);
    d_instantiate(dentry, child);
    return ALEQFS_MKDIR_OK;

out_release:
    aleqfs_inode_release(sb, ino);
    return ALEQFS_MKRET_ERR(err);
}

static int aleqfs_create(struct mnt_idmap *idmap, struct inode *dir,
                         struct dentry *dentry, umode_t mode, bool excl)
{
    struct super_block *sb = dir->i_sb;
    struct aleqfs_inode ei;
    struct inode *child;
    uint64_t ino;
    int err;

    err = aleqfs_inode_alloc(sb, &ino);
    if (err)
        return err;

    aleqfs_init_disk_inode(&ei, S_IFREG | (mode & 07777), 1);
    ei.decoherence_stamp = ktime_get_real_seconds();

    err = aleqfs_inode_dirty(sb, ino, &ei);
    if (err)
        goto out_release;

    err = aleqfs_dir_add_entry(sb, dir->i_ino, ino,
                               (const unsigned char *)dentry->d_name.name,
                               dentry->d_name.len);
    if (err)
        goto out_release;

    child = aleqfs_iget(sb, ino);
    if (IS_ERR(child)) {
        err = PTR_ERR(child);
        aleqfs_dir_remove_entry(sb, dir->i_ino,
                                (const unsigned char *)dentry->d_name.name,
                                dentry->d_name.len);
        goto out_release;
    }

    mark_inode_dirty(dir);
    d_instantiate(dentry, child);
    return 0;

out_release:
    aleqfs_inode_release(sb, ino);
    return err;
}

static int aleqfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *child = d_inode(dentry);
    int ret;

    if (!child)
        return -ENOENT;
    if (S_ISDIR(child->i_mode))
        return -EISDIR;

    ret = aleqfs_dir_remove_entry(sb, dir->i_ino,
                                  (const unsigned char *)dentry->d_name.name,
                                  dentry->d_name.len);
    if (ret)
        return ret;

    /* blocks and the disk inode are reclaimed by ->evict_inode */
    drop_nlink(child);
    ALEQFS_SET_CTIME(child, ktime_get_real_seconds(), 0);
    mark_inode_dirty(child);
    return 0;
}

static int aleqfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = dir->i_sb;
    struct inode *child = d_inode(dentry);
    int ret;

    if (!child)
        return -ENOENT;
    if (!S_ISDIR(child->i_mode))
        return -ENOTDIR;
    if (!aleqfs_dir_empty(sb, child->i_ino))
        return -ENOTEMPTY;

    ret = aleqfs_dir_remove_entry(sb, dir->i_ino,
                                  (const unsigned char *)dentry->d_name.name,
                                  dentry->d_name.len);
    if (ret)
        return ret;

    clear_nlink(child);
    mark_inode_dirty(child);
    inode_dec_link_count(dir);
    mark_inode_dirty(dir);
    return 0;
}

static int aleqfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
                         struct dentry *old_dentry, struct inode *new_dir,
                         struct dentry *new_dentry, unsigned int flags)
{
    struct super_block *sb = old_dir->i_sb;
    struct inode *child = d_inode(old_dentry);
    struct inode *victim = d_inode(new_dentry);
    int ret;

    if (!child)
        return -ENOENT;
    if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT))
        return -EINVAL;
    if (flags & RENAME_NOREPLACE && victim)
        return -EEXIST;

    if (victim) {
        if (S_ISDIR(victim->i_mode)) {
            if (!S_ISDIR(child->i_mode))
                return -EISDIR;
            if (!aleqfs_dir_empty(sb, victim->i_ino))
                return -ENOTEMPTY;
        } else if (S_ISDIR(child->i_mode)) {
            return -ENOTDIR;
        }
    }

    ret = aleqfs_dir_remove_entry(sb, old_dir->i_ino,
                                  (const unsigned char *)old_dentry->d_name.name,
                                  old_dentry->d_name.len);
    if (ret)
        return ret;

    ret = aleqfs_dir_add_entry(sb, new_dir->i_ino, child->i_ino,
                               (const unsigned char *)new_dentry->d_name.name,
                               new_dentry->d_name.len);
    if (ret) {
        /* put the source entry back so the file is not lost */
        aleqfs_dir_add_entry(sb, old_dir->i_ino, child->i_ino,
                             (const unsigned char *)old_dentry->d_name.name,
                             old_dentry->d_name.len);
        return ret;
    }

    if (victim) {
        /* the replaced inode is reclaimed by ->evict_inode */
        if (S_ISDIR(victim->i_mode))
            clear_nlink(victim);
        else
            drop_nlink(victim);
        mark_inode_dirty(victim);
        if (S_ISDIR(victim->i_mode) && new_dir != old_dir)
            inode_dec_link_count(new_dir);
    }

    if (S_ISDIR(child->i_mode) && old_dir != new_dir) {
        inode_dec_link_count(old_dir);
        inode_inc_link_count(new_dir);
        mark_inode_dirty(old_dir);
        mark_inode_dirty(new_dir);
    }
    return 0;
}

static const struct inode_operations aleqfs_dir_inode_ops = {
    .lookup  = aleqfs_lookup,
    .mkdir   = aleqfs_mkdir,
    .create  = aleqfs_create,
    .unlink  = aleqfs_unlink,
    .rmdir   = aleqfs_rmdir,
    .rename  = aleqfs_rename,
    .getattr = aleqfs_getattr,
    .setattr = aleqfs_setattr,
};

static const struct file_operations aleqfs_dir_ops = {
    .owner   = THIS_MODULE,
    .open    = aleqfs_open,
    .release = aleqfs_release,
    .iterate_shared = aleqfs_iterate,
    .llseek  = generic_file_llseek,
};

static const struct inode_operations aleqfs_inode_ops = {
    .getattr = aleqfs_getattr,
    .setattr = aleqfs_setattr,
};

/* ---- superblock -------------------------------------------------------- */

static void aleqfs_put_super(struct super_block *sb)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    if (sbi) {
        /* re-seal and make sure the superblock reaches the device:
         * kill_bdev() invalidates buffers right after this hook */
        aleqfs_super_sync(sb);
        if (sbi->sb_bh) {
            sync_dirty_buffer(sbi->sb_bh);
            brelse(sbi->sb_bh);
        }
        mutex_destroy(&sbi->s_lock);
        kfree(sbi);
        sb->s_fs_info = NULL;
    }
}

static int aleqfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    buf->f_type    = ALEQFS_MAGIC;
    buf->f_bsize   = sbi->block_size;
    buf->f_blocks  = sbi->total_blocks;
    buf->f_bfree   = sbi->sb->free_blocks;
    buf->f_bavail  = sbi->sb->free_blocks;
    buf->f_files   = sbi->inode_count;
    buf->f_ffree   = sbi->sb->free_inodes;
    buf->f_frsize  = sbi->block_size;
    buf->f_namelen = ALEQFS_MAX_NAME;
    return 0;
}

static int aleqfs_sync_fs(struct super_block *sb, int wait)
{
    struct aleqfs_sb_info *sbi = ALEQFS_SB(sb);

    aleqfs_super_sync(sb);
    if (wait && sbi->sb_bh)
        sync_dirty_buffer(sbi->sb_bh);
    return 0;
}

static const struct super_operations aleqfs_super_ops = {
    .write_inode   = aleqfs_write_inode,
    .evict_inode   = aleqfs_evict_inode,
    .put_super     = aleqfs_put_super,
    .sync_fs       = aleqfs_sync_fs,
    .statfs        = aleqfs_statfs,
};

static int aleqfs_validate_sb(struct super_block *sb,
                              struct aleqfs_superblock *disk_sb,
                              bool silent)
{
    loff_t dev_size;
    uint64_t dev_blocks;
    uint64_t expected_seal;

    if (disk_sb->magic != ALEQFS_MAGIC) {
        if (!silent)
            pr_err("aleqfs: wrong magic 0x%llx\n",
                   (unsigned long long)disk_sb->magic);
        return -EINVAL;
    }
    if (disk_sb->version != ALEQFS_FS_VERSION) {
        pr_err("aleqfs: unsupported version %u (expected %u)\n",
               disk_sb->version, ALEQFS_FS_VERSION);
        return -EFSCORRUPTED;
    }
    if (disk_sb->block_size != ALEQFS_BLOCK_SIZE) {
        pr_err("aleqfs: unsupported block size %u\n", disk_sb->block_size);
        return -EFSCORRUPTED;
    }
    if (disk_sb->inode_count !=
        (uint64_t)ALEQFS_INODE_BLOCKS * ALEQFS_INODES_PER_BLK) {
        pr_err("aleqfs: bad inode count %llu\n",
               (unsigned long long)disk_sb->inode_count);
        return -EFSCORRUPTED;
    }
    if (disk_sb->journal_start < 1 ||
        disk_sb->journal_blocks != ALEQFS_JOURNAL_BLOCKS ||
        disk_sb->journal_start + disk_sb->journal_blocks >
            disk_sb->inode_table_start ||
        disk_sb->inode_table_start + ALEQFS_INODE_BLOCKS >
            disk_sb->bitmap_start ||
        disk_sb->bitmap_start + ALEQFS_BITMAP_BLOCKS > disk_sb->data_start ||
        disk_sb->data_start >= disk_sb->total_blocks) {
        pr_err("aleqfs: inconsistent on-disk geometry\n");
        return -EFSCORRUPTED;
    }
    if (disk_sb->root_inode == 0 ||
        disk_sb->root_inode > disk_sb->inode_count) {
        pr_err("aleqfs: bad root inode %llu\n",
               (unsigned long long)disk_sb->root_inode);
        return -EFSCORRUPTED;
    }
    if (disk_sb->entanglement_blocks > 64) {
        pr_err("aleqfs: bad entanglement area\n");
        return -EFSCORRUPTED;
    }

    dev_size = (loff_t)bdev_nr_sectors(sb->s_bdev) << SECTOR_SHIFT;
    dev_blocks = (uint64_t)dev_size / ALEQFS_BLOCK_SIZE;
    if (disk_sb->total_blocks > dev_blocks) {
        pr_err("aleqfs: fs size %llu blocks exceeds device %llu blocks\n",
               (unsigned long long)disk_sb->total_blocks,
               (unsigned long long)dev_blocks);
        return -EFSCORRUPTED;
    }

    /* decoherence detection: verify the superblock seal when present */
    if (disk_sb->checksum != 0) {
        uint64_t saved = disk_sb->checksum;

        disk_sb->checksum = 0;
        expected_seal = aleqfs_fnv1a(disk_sb, ALEQFS_BLOCK_SIZE);
        disk_sb->checksum = saved;
        if (saved != expected_seal) {
            pr_err("aleqfs: superblock decoherence detected (checksum mismatch)\n");
            return -EFSCORRUPTED;
        }
    }

    return 0;
}

static int aleqfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct aleqfs_sb_info *sbi;
    struct buffer_head *bh;
    struct inode *root_inode;
    int ret;

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;

    sb->s_fs_info = sbi;
    mutex_init(&sbi->s_lock);

    if (!sb_set_blocksize(sb, ALEQFS_BLOCK_SIZE)) {
        pr_err("aleqfs: block size %u not supported by device\n",
               ALEQFS_BLOCK_SIZE);
        ret = -EINVAL;
        goto fail;
    }

    bh = sb_bread(sb, 0);
    if (!bh) {
        ret = -EIO;
        goto fail;
    }

    ret = aleqfs_validate_sb(sb, (struct aleqfs_superblock *)bh->b_data,
                             !!(sb->s_flags & SB_SILENT));
    brelse(bh);
    if (ret)
        goto fail;

    /* re-read through the pinned superblock buffer we keep around */
    bh = sb_bread(sb, 0);
    if (!bh) {
        ret = -EIO;
        goto fail;
    }
    sbi->sb = (struct aleqfs_superblock *)bh->b_data;
    sbi->sb_bh = bh;

    sbi->block_size        = ALEQFS_BLOCK_SIZE;
    sbi->total_blocks      = sbi->sb->total_blocks;
    sbi->inode_count       = sbi->sb->inode_count;
    sbi->inode_table_start = sbi->sb->inode_table_start;
    sbi->data_start        = sbi->sb->data_start;

    sb->s_magic    = ALEQFS_MAGIC;
    sb->s_op       = &aleqfs_super_ops;
    sb->s_maxbytes = min_t(loff_t, MAX_LFS_FILESIZE,
                           (loff_t)sbi->total_blocks * ALEQFS_BLOCK_SIZE);

    root_inode = aleqfs_iget(sb, sbi->sb->root_inode);
    if (IS_ERR(root_inode)) {
        ret = PTR_ERR(root_inode);
        goto fail;
    }
    if (!S_ISDIR(root_inode->i_mode)) {
        iput(root_inode);
        ret = -EFSCORRUPTED;
        goto fail;
    }

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        ret = -ENOMEM;
        goto fail;
    }

    return 0;

fail:
    sb->s_fs_info = NULL;
    if (sbi->sb_bh)
        brelse(sbi->sb_bh);
    mutex_destroy(&sbi->s_lock);
    kfree(sbi);
    return ret;
}

static int aleqfs_get_tree(struct fs_context *fc)
{
    return get_tree_bdev(fc, aleqfs_fill_super);
}

static const struct fs_context_operations aleqfs_context_ops = {
    .get_tree = aleqfs_get_tree,
};

static int aleqfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &aleqfs_context_ops;
    return 0;
}

static struct file_system_type aleqfs_fs_type = {
    .owner           = THIS_MODULE,
    .name            = ALEQFS_MOD_NAME,
    .init_fs_context = aleqfs_init_fs_context,
    .kill_sb         = kill_block_super,
    .fs_flags        = FS_REQUIRES_DEV,
};

static int __init aleqfs_init(void)
{
    int ret = register_filesystem(&aleqfs_fs_type);

    if (ret)
        pr_err("aleqfs: failed to register (%d)\n", ret);
    else
        pr_info("aleqfs: module loaded v%s\n", ALEQFS_MOD_VER);
    return ret;
}

static void __exit aleqfs_exit(void)
{
    unregister_filesystem(&aleqfs_fs_type);
    pr_info("aleqfs: module unloaded\n");
}

module_init(aleqfs_init);
module_exit(aleqfs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AleQFS Contributors");
MODULE_DESCRIPTION(ALEQFS_MOD_DESC);
MODULE_VERSION(ALEQFS_MOD_VER);
MODULE_ALIAS_FS(ALEQFS_MOD_NAME);
