#include "aleqfs.h"
#include <string.h>
#include <errno.h>

uint64_t aleqfs_super_seal(const struct aleqfs_superblock *sb)
{
    uint8_t tmp[ALEQFS_BLOCK_SIZE];
    memcpy(tmp, sb, sizeof(tmp));
    struct aleqfs_superblock *copy = (struct aleqfs_superblock *)tmp;
    copy->checksum = 0;
    return aleqfs_checksum(tmp, sizeof(tmp));
}

/*
 * Validate every on-disk superblock field we are about to trust. A corrupt
 * or hostile image must be rejected here, not deep inside a block loop.
 */
static int super_validate(struct aleqfs_dev *dev, uint64_t real_blocks)
{
    const struct aleqfs_superblock *sb = &dev->sb;

    if (sb->magic != ALEQFS_MAGIC)
        return -EINVAL;
    if (sb->version != ALEQFS_FS_VERSION)
        return -EINVAL;
    if (sb->block_size != ALEQFS_BLOCK_SIZE)
        return -EINVAL;
    if (sb->inode_count != (uint64_t)ALEQFS_INODE_BLOCKS * ALEQFS_INODES_PER_BLK)
        return -EINVAL;

    if (sb->journal_start < 1 || sb->journal_blocks != ALEQFS_JOURNAL_BLOCKS)
        return -EINVAL;
    if (sb->journal_start + sb->journal_blocks > sb->inode_table_start)
        return -EINVAL;
    if (sb->inode_table_start + ALEQFS_INODE_BLOCKS > sb->bitmap_start)
        return -EINVAL;
    if (sb->bitmap_start + ALEQFS_BITMAP_BLOCKS > sb->data_start)
        return -EINVAL;
    if (sb->data_start + ALEQFS_MIN_DATA_BLOCKS > sb->total_blocks)
        return -EINVAL;
    if (sb->total_blocks > ALEQFS_MAX_BLOCKS)
        return -EINVAL;

    /* the fs must fit in the backing file / device */
    if (real_blocks && sb->total_blocks > real_blocks)
        return -EINVAL;

    if (sb->root_inode == 0 || sb->root_inode > sb->inode_count)
        return -EINVAL;

    if (sb->grover_root != 0 && !aleqfs_block_sane(dev, sb->grover_root))
        return -EINVAL;

    if (sb->entanglement_blocks > 64)
        return -EINVAL;
    if (sb->entanglement_blocks > 0) {
        if (!aleqfs_block_sane(dev, sb->entanglement_start))
            return -EINVAL;
        if (sb->entanglement_start + sb->entanglement_blocks > sb->total_blocks)
            return -EINVAL;
    }

    if (sb->free_blocks > sb->total_blocks || sb->free_inodes > sb->inode_count)
        return -EINVAL;

    return 0;
}

int aleqfs_super_format(struct aleqfs_dev *dev, uint64_t total_blocks)
{
    struct aleqfs_superblock *sb = &dev->sb;
    uint64_t data_start = 1 + ALEQFS_JOURNAL_BLOCKS + ALEQFS_INODE_BLOCKS +
                          ALEQFS_BITMAP_BLOCKS;

    if (total_blocks < data_start + ALEQFS_MIN_DATA_BLOCKS)
        return -ENOSPC;
    if (total_blocks > ALEQFS_MAX_BLOCKS)
        return -E2BIG;

    memset(sb, 0, sizeof(*sb));

    sb->magic           = ALEQFS_MAGIC;
    sb->version         = ALEQFS_FS_VERSION;
    sb->block_size      = ALEQFS_BLOCK_SIZE;
    sb->total_blocks    = total_blocks;
    sb->inode_count     = ALEQFS_INODE_BLOCKS * ALEQFS_INODES_PER_BLK;
    sb->free_inodes     = sb->inode_count;
    sb->root_inode      = ALEQFS_ROOT_INO;
    sb->journal_start   = 1;
    sb->journal_blocks  = ALEQFS_JOURNAL_BLOCKS;
    sb->inode_table_start = sb->journal_start + sb->journal_blocks;
    sb->bitmap_start    = sb->inode_table_start + ALEQFS_INODE_BLOCKS;
    sb->data_start      = sb->bitmap_start + ALEQFS_BITMAP_BLOCKS;
    sb->grover_root     = 0;
    sb->quantum_temperature = 0.01;
    sb->decoherence_rate    = 0.001;

    dev->num_blocks = total_blocks;
    dev->block_size = ALEQFS_BLOCK_SIZE;
    dev->dirty      = false;
    sb->free_blocks = total_blocks - sb->data_start;

    int ret = aleqfs_dev_write(dev, 0, sb);
    if (ret) return ret;

    uint8_t zero_buf[ALEQFS_BLOCK_SIZE] = {0};
    for (uint64_t b = sb->journal_start; b < sb->data_start; b++) {
        ret = aleqfs_dev_write(dev, b, zero_buf);
        if (ret) return ret;
    }

    ret = aleqfs_bitmap_init(dev);
    if (ret) return ret;

    {
        uint64_t grover_block = 0;
        ret = aleqfs_grover_init(dev, &grover_block);
        if (ret) return ret;
        sb->grover_root = grover_block;
    }

    /* entanglement records live in one contiguous 16-block region */
    {
        struct aleqfs_extent ext;
        sb->entanglement_blocks = 16;
        ret = aleqfs_extent_alloc(dev, sb->entanglement_blocks, &ext);
        if (ret) return ret;
        sb->entanglement_start = ext.start;
        for (uint64_t i = 0; i < ext.count; i++) {
            ret = aleqfs_dev_write(dev, ext.start + i, zero_buf);
            if (ret) return ret;
        }
    }

    uint64_t root_ino;
    ret = aleqfs_inode_alloc(dev, &root_ino);
    if (ret) return ret;

    struct aleqfs_inode root_inode;
    memset(&root_inode, 0, sizeof(root_inode));
    root_inode.mode   = S_IFDIR | 0755;
    root_inode.uid    = getuid();
    root_inode.gid    = getgid();
    root_inode.links  = 2;
    root_inode.atime  = root_inode.mtime = root_inode.ctime = time(NULL);
    root_inode.amplitude.real = 32767;
    root_inode.amplitude.imag = 0;
    ret = aleqfs_inode_write(dev, root_ino, &root_inode);
    if (ret) return ret;

    sb->root_inode = root_ino;
    dev->dirty = true;

    return aleqfs_super_sync(dev);
}

int aleqfs_super_load(struct aleqfs_dev *dev)
{
    uint64_t real_blocks = dev->num_blocks;

    int ret = aleqfs_dev_read(dev, 0, &dev->sb);
    if (ret) return ret;
    if (dev->sb.magic != ALEQFS_MAGIC)
        return -EINVAL;

    ret = super_validate(dev, real_blocks);
    if (ret) return ret;

    /* decoherence detection: verify the superblock seal when present */
    if (dev->sb.checksum != 0 &&
        dev->sb.checksum != aleqfs_super_seal(&dev->sb)) {
        fprintf(stderr,
                "aleqfs: superblock decoherence detected (checksum mismatch)\n");
        return -EBADMSG;
    }

    dev->num_blocks = dev->sb.total_blocks;
    dev->block_size = dev->sb.block_size;

    /* the root inode must exist and be a directory */
    struct aleqfs_inode root;
    ret = aleqfs_inode_read(dev, dev->sb.root_inode, &root);
    if (ret) return ret;
    if (root.mode == 0 || !S_ISDIR(root.mode))
        return -EINVAL;

    int recovered = aleqfs_journal_recover(dev);
    if (recovered < 0)
        return recovered;

    /* legacy images without a seal get one on the next sync */
    if (dev->sb.checksum == 0)
        dev->dirty = true;

    return 0;
}

int aleqfs_super_sync(struct aleqfs_dev *dev)
{
    dev->sb.checksum = aleqfs_super_seal(&dev->sb);
    int ret = aleqfs_dev_write(dev, 0, &dev->sb);
    if (ret) return ret;
    dev->dirty = false;
    return 0;
}
