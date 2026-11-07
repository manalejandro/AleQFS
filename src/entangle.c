#include "aleqfs.h"
#include <errno.h>

#define ENTANGLE_MAX_BLOCKS 64
#define ENTANGLE_RECORDS_PER_BLK \
    (ALEQFS_BLOCK_SIZE / sizeof(struct aleqfs_entanglement_record))

static int entangle_region_ok(struct aleqfs_dev *dev)
{
    if (dev->sb.entanglement_blocks == 0 ||
        dev->sb.entanglement_blocks > ENTANGLE_MAX_BLOCKS)
        return 0;
    if (!aleqfs_block_sane(dev, dev->sb.entanglement_start))
        return 0;
    if (dev->sb.entanglement_start + dev->sb.entanglement_blocks >
        dev->sb.total_blocks)
        return 0;
    return 1;
}

static int entangle_ino_ok(struct aleqfs_dev *dev, uint64_t ino)
{
    struct aleqfs_inode inode;
    if (ino == 0 || ino > dev->sb.inode_count)
        return 0;
    if (aleqfs_inode_read(dev, ino, &inode) != 0)
        return 0;
    return inode.mode != 0;
}

int aleqfs_entangle(struct aleqfs_dev *dev, uint64_t ino_a, uint64_t ino_b, uint64_t ops)
{
    uint64_t start = dev->sb.entanglement_start;
    struct aleqfs_inode inode_a, inode_b;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_entanglement_record *recs;
    int free_block = -1, free_slot = -1;
    int found = 0;
    int ret;

    if (!entangle_region_ok(dev))
        return -EINVAL;
    if (ino_a == 0 || ino_b == 0 || ino_a == ino_b)
        return -EINVAL;
    if (!entangle_ino_ok(dev, ino_a) || !entangle_ino_ok(dev, ino_b))
        return -ENOENT;

    uint64_t nblocks = dev->sb.entanglement_blocks;

    for (uint64_t b = 0; b < nblocks && !found; b++) {
        ret = aleqfs_dev_read(dev, start + b, buf);
        if (ret < 0)
            return ret;

        recs = (struct aleqfs_entanglement_record *)buf;
        for (uint64_t i = 0; i < ENTANGLE_RECORDS_PER_BLK; i++) {
            if ((recs[i].ino_a == ino_a && recs[i].ino_b == ino_b) ||
                (recs[i].ino_a == ino_b && recs[i].ino_b == ino_a)) {
                recs[i].established = time(NULL);
                recs[i].ops = ops;
                ret = aleqfs_dev_write(dev, start + b, buf);
                if (ret < 0)
                    return ret;
                found = 1;
                break;
            }
            if (free_block < 0 && recs[i].ino_a == 0 && recs[i].ino_b == 0) {
                free_block = (int)b;
                free_slot = (int)i;
            }
        }
    }

    if (!found) {
        if (free_block < 0)
            return -ENOSPC;

        ret = aleqfs_dev_read(dev, start + (uint64_t)free_block, buf);
        if (ret < 0)
            return ret;

        recs = (struct aleqfs_entanglement_record *)buf;
        recs[free_slot].ino_a = ino_a;
        recs[free_slot].ino_b = ino_b;
        recs[free_slot].established = time(NULL);
        recs[free_slot].ops = ops;

        ret = aleqfs_dev_write(dev, start + (uint64_t)free_block, buf);
        if (ret < 0)
            return ret;
    }

    ret = aleqfs_inode_read(dev, ino_a, &inode_a);
    if (ret < 0)
        return ret;
    inode_a.entanglement_partner = ino_b;
    inode_a.entanglement_ops = ops;
    ret = aleqfs_inode_write(dev, ino_a, &inode_a);
    if (ret < 0)
        return ret;

    ret = aleqfs_inode_read(dev, ino_b, &inode_b);
    if (ret < 0)
        return ret;
    inode_b.entanglement_partner = ino_a;
    inode_b.entanglement_ops = ops;
    ret = aleqfs_inode_write(dev, ino_b, &inode_b);
    if (ret < 0)
        return ret;

    return 0;
}

int aleqfs_entangle_break(struct aleqfs_dev *dev, uint64_t ino_a, uint64_t ino_b)
{
    uint64_t start = dev->sb.entanglement_start;
    struct aleqfs_inode inode_a, inode_b;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_entanglement_record *recs;
    int ret;

    if (!entangle_region_ok(dev))
        return -EINVAL;

    uint64_t nblocks = dev->sb.entanglement_blocks;

    for (uint64_t b = 0; b < nblocks; b++) {
        ret = aleqfs_dev_read(dev, start + b, buf);
        if (ret < 0)
            return ret;

        recs = (struct aleqfs_entanglement_record *)buf;
        for (uint64_t i = 0; i < ENTANGLE_RECORDS_PER_BLK; i++) {
            if ((recs[i].ino_a == ino_a && recs[i].ino_b == ino_b) ||
                (recs[i].ino_a == ino_b && recs[i].ino_b == ino_a)) {
                memset(&recs[i], 0, sizeof(recs[i]));
                ret = aleqfs_dev_write(dev, start + b, buf);
                if (ret < 0)
                    return ret;

                ret = aleqfs_inode_read(dev, ino_a, &inode_a);
                if (ret < 0)
                    return ret;
                inode_a.entanglement_partner = 0;
                inode_a.entanglement_ops = 0;
                ret = aleqfs_inode_write(dev, ino_a, &inode_a);
                if (ret < 0)
                    return ret;

                ret = aleqfs_inode_read(dev, ino_b, &inode_b);
                if (ret < 0)
                    return ret;
                inode_b.entanglement_partner = 0;
                inode_b.entanglement_ops = 0;
                ret = aleqfs_inode_write(dev, ino_b, &inode_b);
                if (ret < 0)
                    return ret;

                return 0;
            }
        }
    }

    return -ENOENT;
}

int aleqfs_entangle_mirror(struct aleqfs_dev *dev, uint64_t src_ino,
                           uint64_t *mirror_ino)
{
    uint64_t start = dev->sb.entanglement_start;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_entanglement_record *recs;
    int ret;

    if (!entangle_region_ok(dev))
        return -EINVAL;

    uint64_t nblocks = dev->sb.entanglement_blocks;

    for (uint64_t b = 0; b < nblocks; b++) {
        ret = aleqfs_dev_read(dev, start + b, buf);
        if (ret < 0)
            return ret;

        recs = (struct aleqfs_entanglement_record *)buf;
        for (uint64_t i = 0; i < ENTANGLE_RECORDS_PER_BLK; i++) {
            if (recs[i].ino_a == src_ino && recs[i].ino_b != 0) {
                *mirror_ino = recs[i].ino_b;
                return 0;
            }
            if (recs[i].ino_b == src_ino && recs[i].ino_a != 0) {
                *mirror_ino = recs[i].ino_a;
                return 0;
            }
        }
    }

    return -ENOENT;
}

int aleqfs_entanglement_read(struct aleqfs_dev *dev, uint64_t ino,
                             struct aleqfs_entanglement_record *rec)
{
    uint64_t start = dev->sb.entanglement_start;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_entanglement_record *recs;
    int ret;

    if (!entangle_region_ok(dev))
        return -EINVAL;

    uint64_t nblocks = dev->sb.entanglement_blocks;

    for (uint64_t b = 0; b < nblocks; b++) {
        ret = aleqfs_dev_read(dev, start + b, buf);
        if (ret < 0)
            return ret;

        recs = (struct aleqfs_entanglement_record *)buf;
        for (uint64_t i = 0; i < ENTANGLE_RECORDS_PER_BLK; i++) {
            if (recs[i].ino_a == ino || recs[i].ino_b == ino) {
                memcpy(rec, &recs[i], sizeof(*rec));
                return 0;
            }
        }
    }

    return -ENOENT;
}
