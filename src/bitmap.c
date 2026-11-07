#include "aleqfs.h"
#include <string.h>
#include <errno.h>

#define BITS_PER_BLK (ALEQFS_BLOCK_SIZE * 8)

static uint8_t bitmap_cache[ALEQFS_BITMAP_BLOCKS][ALEQFS_BLOCK_SIZE];
static bool bitmap_dirty[ALEQFS_BITMAP_BLOCKS];
static bool bitmap_loaded[ALEQFS_BITMAP_BLOCKS];
static struct aleqfs_dev *bitmap_owner;

/*
 * The cache is process-global; make sure it belongs to the device we are
 * operating on. Bitmap blocks are written through on every mutation, so
 * dropping a stale cache is always safe.
 */
static void bitmap_ensure_owner(struct aleqfs_dev *dev)
{
    if (bitmap_owner != dev) {
        memset(bitmap_loaded, 0, sizeof(bitmap_loaded));
        memset(bitmap_dirty, 0, sizeof(bitmap_dirty));
        bitmap_owner = dev;
    }
}

static int bitmap_load(struct aleqfs_dev *dev, uint64_t blk_idx)
{
    if (blk_idx >= ALEQFS_BITMAP_BLOCKS)
        return -EINVAL;
    bitmap_ensure_owner(dev);
    if (bitmap_loaded[blk_idx])
        return 0;
    int ret = aleqfs_dev_read(dev, dev->sb.bitmap_start + blk_idx,
                              bitmap_cache[blk_idx]);
    if (ret < 0)
        return ret;
    bitmap_loaded[blk_idx] = true;
    bitmap_dirty[blk_idx] = false;
    return 0;
}

static int bitmap_save(struct aleqfs_dev *dev, uint64_t blk_idx)
{
    if (blk_idx >= ALEQFS_BITMAP_BLOCKS)
        return -EINVAL;
    if (!bitmap_dirty[blk_idx])
        return 0;
    int ret = aleqfs_dev_write(dev, dev->sb.bitmap_start + blk_idx,
                               bitmap_cache[blk_idx]);
    if (ret < 0)
        return ret;
    bitmap_dirty[blk_idx] = false;
    return 0;
}

static int bitmap_load_all(struct aleqfs_dev *dev)
{
    for (uint64_t i = 0; i < ALEQFS_BITMAP_BLOCKS; i++) {
        int ret = bitmap_load(dev, i);
        if (ret < 0)
            return ret;
    }
    return 0;
}

static int bitmap_save_all(struct aleqfs_dev *dev)
{
    for (uint64_t i = 0; i < ALEQFS_BITMAP_BLOCKS; i++) {
        int ret = bitmap_save(dev, i);
        if (ret < 0)
            return ret;
    }
    return 0;
}

int aleqfs_bitmap_init(struct aleqfs_dev *dev)
{
    bitmap_ensure_owner(dev);
    memset(bitmap_loaded, 0, sizeof(bitmap_loaded));
    memset(bitmap_dirty, 0, sizeof(bitmap_dirty));
    for (uint64_t i = 0; i < ALEQFS_BITMAP_BLOCKS; i++) {
        memset(bitmap_cache[i], 0, ALEQFS_BLOCK_SIZE);
        bitmap_loaded[i] = true;
        bitmap_dirty[i] = true;
    }

    uint64_t data_start = dev->sb.data_start;
    for (uint64_t blk = 0; blk < data_start; blk++) {
        uint64_t bb = blk / BITS_PER_BLK;
        if (bb >= ALEQFS_BITMAP_BLOCKS)
            break;
        uint64_t off = blk % BITS_PER_BLK;
        uint64_t byte_off = off / 8;
        uint8_t bit = 1 << (off % 8);
        bitmap_cache[bb][byte_off] |= bit;
    }

    dev->sb.free_blocks = dev->sb.total_blocks - data_start;
    dev->dirty = true;

    return bitmap_save_all(dev);
}

int aleqfs_bitmap_alloc(struct aleqfs_dev *dev, uint64_t *block)
{
    int ret = bitmap_load_all(dev);
    if (ret < 0)
        return ret;

    for (uint64_t blk = dev->sb.data_start; blk < dev->sb.total_blocks; blk++) {
        uint64_t bb = blk / BITS_PER_BLK;
        if (bb >= ALEQFS_BITMAP_BLOCKS)
            break;
        uint64_t off = blk % BITS_PER_BLK;
        uint64_t byte_off = off / 8;
        uint8_t bit = 1 << (off % 8);

        if (!(bitmap_cache[bb][byte_off] & bit)) {
            bitmap_cache[bb][byte_off] |= bit;
            bitmap_dirty[bb] = true;
            bitmap_save(dev, bb);
            if (dev->sb.free_blocks > 0)
                dev->sb.free_blocks--;
            dev->dirty = true;
            *block = blk;
            return 0;
        }
    }

    return -ENOSPC;
}

int aleqfs_bitmap_free(struct aleqfs_dev *dev, uint64_t block)
{
    if (!aleqfs_block_sane(dev, block))
        return 0;

    uint64_t bb = block / BITS_PER_BLK;
    if (bb >= ALEQFS_BITMAP_BLOCKS)
        return 0;

    int ret = bitmap_load(dev, bb);
    if (ret < 0)
        return ret;

    uint64_t off = block % BITS_PER_BLK;
    uint64_t byte_off = off / 8;
    uint8_t bit = 1 << (off % 8);

    if (!(bitmap_cache[bb][byte_off] & bit))
        return 0; /* double free: ignore, keep counters consistent */

    bitmap_cache[bb][byte_off] &= ~bit;
    bitmap_dirty[bb] = true;
    bitmap_save(dev, bb);
    dev->sb.free_blocks++;
    dev->dirty = true;

    return 0;
}

void aleqfs_bitmark_set(struct aleqfs_dev *dev, uint64_t block)
{
    if (block >= dev->sb.total_blocks)
        return;

    uint64_t bb = block / BITS_PER_BLK;
    if (bb >= ALEQFS_BITMAP_BLOCKS)
        return;

    bitmap_ensure_owner(dev);
    if (!bitmap_loaded[bb]) {
        if (bitmap_load_all(dev) < 0)
            return;
    }

    uint64_t off = block % BITS_PER_BLK;
    uint64_t byte_off = off / 8;
    uint8_t bit = 1 << (off % 8);

    bitmap_cache[bb][byte_off] |= bit;
    bitmap_dirty[bb] = true;
    bitmap_save(dev, bb);
}

bool aleqfs_bitmap_get(struct aleqfs_dev *dev, uint64_t block)
{
    if (block >= dev->sb.total_blocks)
        return true;

    uint64_t bb = block / BITS_PER_BLK;
    if (bb >= ALEQFS_BITMAP_BLOCKS)
        return true;

    if (bitmap_load_all(dev) < 0)
        return true;

    uint64_t off = block % BITS_PER_BLK;
    uint64_t byte_off = off / 8;
    uint8_t bit = 1 << (off % 8);

    return (bitmap_cache[bb][byte_off] & bit) != 0;
}
