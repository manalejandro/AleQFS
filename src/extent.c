#include "aleqfs.h"
#include <string.h>
#include <errno.h>

static int find_extent(struct aleqfs_dev *dev, const struct aleqfs_inode *inode,
                       uint64_t file_block, uint64_t *phys_block)
{
    uint64_t accum = 0;
    uint32_t ec = aleqfs_extent_count_safe(inode);
    for (uint32_t i = 0; i < ec; i++) {
        if (!aleqfs_extent_sane(dev, &inode->extents[i]))
            return -1;
        if (file_block < accum + inode->extents[i].count) {
            *phys_block = inode->extents[i].start + (file_block - accum);
            return (int)i;
        }
        accum += inode->extents[i].count;
    }
    return -1;
}

static uint64_t total_extent_blocks(const struct aleqfs_inode *inode)
{
    uint64_t total = 0;
    uint32_t ec = aleqfs_extent_count_safe(inode);
    for (uint32_t i = 0; i < ec; i++)
        total += inode->extents[i].count;
    return total;
}

int aleqfs_extent_alloc(struct aleqfs_dev *dev, uint64_t count,
                        struct aleqfs_extent *ext)
{
    if (count == 0)
        return -EINVAL;
    if (count > dev->sb.total_blocks)
        return -ENOSPC;

    for (uint64_t blk = dev->sb.data_start;
         blk + count <= dev->sb.total_blocks;) {
        bool found = true;
        for (uint64_t i = 0; i < count; i++) {
            if (aleqfs_bitmap_get(dev, blk + i)) {
                found = false;
                blk += i + 1;
                break;
            }
        }
        if (found) {
            ext->start = blk;
            ext->count = count;
            for (uint64_t i = 0; i < count; i++)
                aleqfs_bitmark_set(dev, blk + i);
            if (dev->sb.free_blocks >= count)
                dev->sb.free_blocks -= count;
            else
                dev->sb.free_blocks = 0;
            dev->dirty = true;
            return 0;
        }
    }
    return -ENOSPC;
}

int aleqfs_extent_free(struct aleqfs_dev *dev, const struct aleqfs_extent *ext)
{
    if (!aleqfs_extent_sane(dev, ext))
        return 0;
    for (uint64_t i = 0; i < ext->count; i++) {
        int ret = aleqfs_bitmap_free(dev, ext->start + i);
        if (ret < 0)
            return ret;
    }
    return 0;
}

/*
 * Append one physical block to the end of the file mapping: extend the last
 * extent when the next physical block is free, otherwise start a new extent.
 * Returns the newly mapped physical block in *phys; *fresh is true when the
 * block was newly allocated and still holds stale on-disk data (callers must
 * zero it before a partial write to avoid leaking old file contents).
 */
static int append_block(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                        uint64_t *phys, bool *fresh)
{
    uint32_t ec = aleqfs_extent_count_safe(inode);

    *fresh = true;

    if (ec > 0) {
        struct aleqfs_extent *last = &inode->extents[ec - 1];
        if (aleqfs_extent_sane(dev, last)) {
            uint64_t next = last->start + last->count;
            if (next < dev->sb.total_blocks && !aleqfs_bitmap_get(dev, next)) {
                aleqfs_bitmark_set(dev, next);
                last->count++;
                inode->blocks++;
                if (dev->sb.free_blocks > 0)
                    dev->sb.free_blocks--;
                dev->dirty = true;
                *phys = next;
                return 0;
            }
        }
    }

    if (inode->extent_count >= ALEQFS_NR_EXTENTS)
        return -ENOSPC;

    struct aleqfs_extent new_ext;
    int ret = aleqfs_extent_alloc(dev, 1, &new_ext);
    if (ret < 0)
        return ret;

    inode->extents[inode->extent_count] = new_ext;
    inode->extent_count++;
    inode->blocks += new_ext.count;
    *phys = new_ext.start;
    return 0;
}

/*
 * Make sure every file block in [0, file_block] is mapped, zero-filling any
 * hole in between. Without this, extents would no longer describe a
 * contiguous file-block mapping and reads would return wrong data.
 * *fresh reports whether the target block was newly allocated (stale data).
 */
static int ensure_mapped(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                         uint64_t file_block, uint64_t *phys, bool *fresh)
{
    uint8_t zbuf[ALEQFS_BLOCK_SIZE];
    memset(zbuf, 0, sizeof(zbuf));

    *fresh = false;

    for (;;) {
        uint64_t mapped = total_extent_blocks(inode);
        if (mapped > file_block) {
            if (find_extent(dev, inode, file_block, phys) >= 0)
                return 0;
            return -EIO;
        }

        uint64_t blk;
        bool is_fresh = false;
        int ret = append_block(dev, inode, &blk, &is_fresh);
        if (ret < 0)
            return ret;

        if (mapped < file_block) {
            /* intermediate hole block: zero it, it is not the target yet */
            ret = aleqfs_dev_write(dev, blk, zbuf);
            if (ret < 0)
                return ret;
        } else {
            *phys = blk;
            *fresh = is_fresh;
            return 0;
        }
    }
}

int aleqfs_extent_read(struct aleqfs_dev *dev, const struct aleqfs_inode *inode,
                       uint64_t offset, void *buf, uint64_t size)
{
    if (offset >= inode->size)
        return 0;
    if (size > inode->size - offset)
        size = inode->size - offset;

    uint8_t *ptr = (uint8_t *)buf;
    uint64_t remaining = size;

    while (remaining > 0) {
        uint64_t file_block = offset / ALEQFS_BLOCK_SIZE;
        uint64_t block_off = offset % ALEQFS_BLOCK_SIZE;

        uint64_t phys_block;
        if (find_extent(dev, inode, file_block, &phys_block) < 0)
            return -EIO;

        uint64_t to_read = ALEQFS_BLOCK_SIZE - block_off;
        if (to_read > remaining)
            to_read = remaining;

        uint8_t tmp[ALEQFS_BLOCK_SIZE];
        int ret = aleqfs_dev_read(dev, phys_block, tmp);
        if (ret < 0)
            return ret;

        memcpy(ptr, tmp + block_off, to_read);

        ptr += to_read;
        offset += to_read;
        remaining -= to_read;
    }

    return 0;
}

int aleqfs_extent_write(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                        uint64_t offset, const void *buf, uint64_t size)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    uint64_t remaining = size;

    while (remaining > 0) {
        uint64_t file_block = offset / ALEQFS_BLOCK_SIZE;
        uint64_t block_off = offset % ALEQFS_BLOCK_SIZE;

        uint64_t phys_block;
        bool fresh = false;
        int ret = ensure_mapped(dev, inode, file_block, &phys_block, &fresh);
        if (ret < 0)
            return ret;

        uint64_t to_write = ALEQFS_BLOCK_SIZE - block_off;
        if (to_write > remaining)
            to_write = remaining;

        if (block_off == 0 && to_write == ALEQFS_BLOCK_SIZE) {
            ret = aleqfs_dev_write(dev, phys_block, ptr);
            if (ret < 0)
                return ret;
        } else {
            uint8_t tmp[ALEQFS_BLOCK_SIZE];
            if (fresh) {
                /* never expose stale data from previously deleted files */
                memset(tmp, 0, sizeof(tmp));
            } else {
                ret = aleqfs_dev_read(dev, phys_block, tmp);
                if (ret < 0)
                    return ret;
            }
            memcpy(tmp + block_off, ptr, to_write);
            ret = aleqfs_dev_write(dev, phys_block, tmp);
            if (ret < 0)
                return ret;
        }

        ptr += to_write;
        offset += to_write;
        remaining -= to_write;
    }

    if (offset > inode->size)
        inode->size = offset;
    inode->blocks = total_extent_blocks(inode);

    return 0;
}

int aleqfs_extent_append(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                         const void *buf, uint64_t size, uint64_t *bytes_written,
                         uint64_t ino)
{
    uint64_t offset = inode->size;
    const uint8_t *ptr = (const uint8_t *)buf;
    uint64_t remaining = size;
    uint64_t written = 0;
    int ret = 0;

    /* open journal records: one coalesced (start,count) pair per extent */
    struct { uint64_t block; uint64_t count; } jents[ALEQFS_NR_EXTENTS];
    int jcount = 0;

    while (remaining > 0) {
        uint64_t file_block = offset / ALEQFS_BLOCK_SIZE;
        uint64_t block_off = offset % ALEQFS_BLOCK_SIZE;

        uint64_t phys_block;
        bool fresh = false;
        int idx = find_extent(dev, inode, file_block, &phys_block);

        if (idx < 0) {
            ret = append_block(dev, inode, &phys_block, &fresh);
            if (ret < 0)
                break;

            /*
             * Journal the allocation before the data write, coalescing
             * physically adjacent blocks into a single (start,count) record.
             */
            if (jcount > 0 &&
                jents[jcount - 1].block + jents[jcount - 1].count ==
                    phys_block) {
                jents[jcount - 1].count++;
                aleqfs_journal_extend(dev, ino, jents[jcount - 1].block,
                                      jents[jcount - 1].count);
            } else if (jcount < ALEQFS_NR_EXTENTS) {
                jents[jcount].block = phys_block;
                jents[jcount].count = 1;
                aleqfs_journal_record(dev, ino, phys_block, 1);
                jcount++;
            }
        }

        uint64_t to_write = ALEQFS_BLOCK_SIZE - block_off;
        if (to_write > remaining)
            to_write = remaining;

        if (block_off == 0 && to_write == ALEQFS_BLOCK_SIZE) {
            ret = aleqfs_dev_write(dev, phys_block, ptr);
            if (ret < 0)
                break;
        } else {
            uint8_t tmp[ALEQFS_BLOCK_SIZE];
            if (fresh) {
                /* never expose stale data from previously deleted files */
                memset(tmp, 0, sizeof(tmp));
            } else {
                ret = aleqfs_dev_read(dev, phys_block, tmp);
                if (ret < 0)
                    break;
            }
            memcpy(tmp + block_off, ptr, to_write);
            ret = aleqfs_dev_write(dev, phys_block, tmp);
            if (ret < 0)
                break;
        }

        ptr += to_write;
        offset += to_write;
        written += to_write;
        remaining -= to_write;
    }

    inode->size += written;
    inode->blocks = total_extent_blocks(inode);
    inode->mtime = time(NULL);
    *bytes_written = written;

    if (written > 0 && ret == 0) {
        /* seal the first data block for decoherence detection */
        uint64_t first_blk;
        if (find_extent(dev, inode, 0, &first_blk) >= 0) {
            uint8_t tmp[ALEQFS_BLOCK_SIZE];
            if (aleqfs_dev_read(dev, first_blk, tmp) == 0)
                inode->decoherence_stamp = aleqfs_checksum(tmp, sizeof(tmp));
        }

        ret = aleqfs_inode_write(dev, ino, inode);
    }

    if (ret == 0) {
        /* commit succeeded: every journaled allocation is now referenced */
        for (int i = 0; i < jcount; i++)
            aleqfs_journal_clear(dev, ino, jents[i].block, jents[i].count);
    } else {
        /*
         * Roll back: the inode was never committed, so every block we
         * allocated during this call is released again and the journal
         * records are dropped (recovery would free the same blocks).
         */
        for (int i = 0; i < jcount; i++) {
            for (uint64_t k = 0; k < jents[i].count; k++)
                aleqfs_bitmap_free(dev, jents[i].block + k);
            aleqfs_journal_clear(dev, ino, jents[i].block, jents[i].count);
        }
    }

    return ret;
}
