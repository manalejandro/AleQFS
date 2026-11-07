#include "aleqfs.h"
#include <errno.h>

#define GROVER_HASH_BITS 10
#define GROVER_MAX_CHAIN 4096 /* hard cap: corrupt "next" pointers must not loop */

static uint64_t grover_hash(uint64_t key)
{
    return (key * 0x9E3779B97F4A7C15ULL) >> (64 - GROVER_HASH_BITS);
}

uint64_t aleqfs_grover_key(const char *name)
{
    /* FNV-1a over the name; key 0 is reserved for "empty slot" */
    uint64_t key = aleqfs_checksum(name, strlen(name));
    return key ? key : 1;
}

/* num_slots comes from disk: never trust it beyond one block of slots */
static uint16_t node_num_slots(const struct aleqfs_grover_node *node)
{
    if (node->num_slots == 0 || node->num_slots > ALEQFS_GROVER_SLOTS_PER_BLK)
        return ALEQFS_GROVER_SLOTS_PER_BLK;
    return node->num_slots;
}

/* a "next" pointer must reference the data area or be treated as absent */
static uint64_t node_next_safe(struct aleqfs_dev *dev,
                               const struct aleqfs_grover_node *node)
{
    uint64_t next = node->next;
    if (next == 0)
        return 0;
    if (!aleqfs_block_sane(dev, next))
        return 0;
    return next;
}

static int ensure_chain(struct aleqfs_dev *dev, uint64_t root_block,
                        uint64_t idx, uint64_t *block)
{
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    uint64_t cur = root_block;
    uint64_t i = 0;
    int ret;

    if (!aleqfs_block_sane(dev, root_block))
        return -EINVAL;

    while (i < idx) {
        ret = aleqfs_dev_read(dev, cur, buf);
        if (ret < 0)
            return ret;
        uint64_t next = node_next_safe(dev, node);
        if (next == 0) {
            uint64_t new_blk;
            uint8_t new_buf[ALEQFS_BLOCK_SIZE];
            struct aleqfs_grover_node *new_node = (struct aleqfs_grover_node *)new_buf;
            ret = aleqfs_bitmap_alloc(dev, &new_blk);
            if (ret < 0)
                return ret;
            memset(new_buf, 0, sizeof(new_buf));
            new_node->parent = cur;
            new_node->num_slots = ALEQFS_GROVER_SLOTS_PER_BLK;
            ret = aleqfs_dev_write(dev, new_blk, new_buf);
            if (ret < 0) {
                aleqfs_bitmap_free(dev, new_blk);
                return ret;
            }
            node->next = new_blk;
            ret = aleqfs_dev_write(dev, cur, buf);
            if (ret < 0) {
                aleqfs_bitmap_free(dev, new_blk);
                return ret;
            }
            next = new_blk;
        }
        cur = next;
        i++;
    }
    *block = cur;
    return 0;
}

int aleqfs_grover_init(struct aleqfs_dev *dev, uint64_t *root_block)
{
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    int ret;

    ret = aleqfs_bitmap_alloc(dev, root_block);
    if (ret < 0)
        return ret;

    memset(buf, 0, sizeof(buf));
    node->num_slots = ALEQFS_GROVER_SLOTS_PER_BLK;

    ret = aleqfs_dev_write(dev, *root_block, buf);
    if (ret < 0)
        return ret;

    return 0;
}

int aleqfs_grover_insert(struct aleqfs_dev *dev, uint64_t root_block,
                         uint64_t key, uint64_t value,
                         int16_t amp_real, int16_t amp_imag)
{
    if (key == 0)
        return -EINVAL;
    if (root_block == 0 || dev->sb.grover_root == 0)
        return -ENXIO;

    uint64_t hash = grover_hash(key);
    uint64_t start_block_idx = hash / ALEQFS_GROVER_SLOTS_PER_BLK;
    uint64_t start_off = hash % ALEQFS_GROVER_SLOTS_PER_BLK;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    uint64_t blk;
    int ret;

    ret = ensure_chain(dev, root_block, start_block_idx, &blk);
    if (ret < 0)
        return ret;

    /* remember the first tombstone so deletes do not fragment the table */
    uint64_t tomb_blk = 0;
    uint64_t tomb_off = 0;

    for (int guard = 0; guard < GROVER_MAX_CHAIN; guard++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return ret;

        uint16_t ns = node_num_slots(node);
        for (uint64_t i = start_off; i < ns; i++) {
            if (node->slots[i].key == key) {
                node->slots[i].value = value;
                node->slots[i].amplitude_real = amp_real;
                node->slots[i].amplitude_imag = amp_imag;
                node->slots[i].flags = ALEQFS_GROVER_F_USED;
                return aleqfs_dev_write(dev, blk, buf);
            }
            if (node->slots[i].key == 0 &&
                (node->slots[i].flags & ALEQFS_GROVER_F_TOMB)) {
                if (tomb_blk == 0) {
                    tomb_blk = blk;
                    tomb_off = i;
                }
                continue;
            }
            if (node->slots[i].key == 0) {
                /* free slot: prefer recycling an earlier tombstone */
                if (tomb_blk != 0) {
                    uint8_t tbuf[ALEQFS_BLOCK_SIZE];
                    ret = aleqfs_dev_read(dev, tomb_blk, tbuf);
                    if (ret < 0)
                        return ret;
                    struct aleqfs_grover_node *tnode =
                        (struct aleqfs_grover_node *)tbuf;
                    tnode->slots[tomb_off].key = key;
                    tnode->slots[tomb_off].value = value;
                    tnode->slots[tomb_off].amplitude_real = amp_real;
                    tnode->slots[tomb_off].amplitude_imag = amp_imag;
                    tnode->slots[tomb_off].flags = ALEQFS_GROVER_F_USED;
                    return aleqfs_dev_write(dev, tomb_blk, tbuf);
                }
                node->slots[i].key = key;
                node->slots[i].value = value;
                node->slots[i].amplitude_real = amp_real;
                node->slots[i].amplitude_imag = amp_imag;
                node->slots[i].flags = ALEQFS_GROVER_F_USED;
                return aleqfs_dev_write(dev, blk, buf);
            }
        }

        uint64_t next = node_next_safe(dev, node);
        if (next == 0) {
            uint64_t new_blk;
            uint8_t new_buf[ALEQFS_BLOCK_SIZE];
            struct aleqfs_grover_node *new_node = (struct aleqfs_grover_node *)new_buf;
            ret = aleqfs_bitmap_alloc(dev, &new_blk);
            if (ret < 0)
                return ret;
            memset(new_buf, 0, sizeof(new_buf));
            new_node->parent = blk;
            new_node->num_slots = ALEQFS_GROVER_SLOTS_PER_BLK;
            new_node->slots[0].key = key;
            new_node->slots[0].value = value;
            new_node->slots[0].amplitude_real = amp_real;
            new_node->slots[0].amplitude_imag = amp_imag;
            new_node->slots[0].flags = ALEQFS_GROVER_F_USED;
            ret = aleqfs_dev_write(dev, new_blk, new_buf);
            if (ret < 0) {
                aleqfs_bitmap_free(dev, new_blk);
                return ret;
            }
            node->next = new_blk;
            return aleqfs_dev_write(dev, blk, buf);
        }

        blk = next;
        start_off = 0;
    }

    return -ELOOP;
}

int aleqfs_grover_lookup(struct aleqfs_dev *dev, uint64_t root_block,
                         uint64_t key, uint64_t *value)
{
    if (key == 0 || !aleqfs_block_sane(dev, root_block))
        return -EINVAL;

    uint64_t hash = grover_hash(key);
    uint64_t start_block_idx = hash / ALEQFS_GROVER_SLOTS_PER_BLK;
    uint64_t start_off = hash % ALEQFS_GROVER_SLOTS_PER_BLK;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    uint64_t blk = root_block;
    int ret;

    for (uint64_t idx = 0; idx < start_block_idx; idx++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return ret;
        blk = node_next_safe(dev, node);
        if (blk == 0)
            return -ENOENT;
    }

    for (int guard = 0; guard < GROVER_MAX_CHAIN; guard++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return ret;

        uint16_t ns = node_num_slots(node);
        for (uint64_t i = start_off; i < ns; i++) {
            if (node->slots[i].key == key) {
                *value = node->slots[i].value;
                return 0;
            }
            if (node->slots[i].key == 0 &&
                !(node->slots[i].flags & ALEQFS_GROVER_F_TOMB))
                return -ENOENT;
        }

        blk = node_next_safe(dev, node);
        if (blk == 0)
            return -ENOENT;
        start_off = 0;
    }

    return -ELOOP;
}

int aleqfs_grover_delete(struct aleqfs_dev *dev, uint64_t root_block, uint64_t key)
{
    if (key == 0 || !aleqfs_block_sane(dev, root_block))
        return -EINVAL;

    uint64_t hash = grover_hash(key);
    uint64_t start_block_idx = hash / ALEQFS_GROVER_SLOTS_PER_BLK;
    uint64_t start_off = hash % ALEQFS_GROVER_SLOTS_PER_BLK;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    uint64_t blk = root_block;
    int ret;

    for (uint64_t idx = 0; idx < start_block_idx; idx++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return ret;
        blk = node_next_safe(dev, node);
        if (blk == 0)
            return -ENOENT;
    }

    for (int guard = 0; guard < GROVER_MAX_CHAIN; guard++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return ret;

        uint16_t ns = node_num_slots(node);
        for (uint64_t i = start_off; i < ns; i++) {
            if (node->slots[i].key == key) {
                /* tombstone: keeps open-addressing probe chains intact */
                memset(&node->slots[i], 0, sizeof(node->slots[i]));
                node->slots[i].flags = ALEQFS_GROVER_F_TOMB;
                return aleqfs_dev_write(dev, blk, buf);
            }
            if (node->slots[i].key == 0 &&
                !(node->slots[i].flags & ALEQFS_GROVER_F_TOMB))
                return -ENOENT;
        }

        blk = node_next_safe(dev, node);
        if (blk == 0)
            return -ENOENT;
        start_off = 0;
    }

    return -ELOOP;
}

int aleqfs_grover_search(struct aleqfs_dev *dev, uint64_t root_block,
                         uint64_t pattern, uint64_t *results, int max_results)
{
    if (root_block == 0 || !aleqfs_block_sane(dev, root_block))
        return 0;
    if (max_results <= 0)
        return 0;

    uint8_t buf[ALEQFS_BLOCK_SIZE];
    struct aleqfs_grover_node *node = (struct aleqfs_grover_node *)buf;
    uint64_t blk = root_block;
    int found = 0;
    int ret;

    for (int guard = 0; guard < GROVER_MAX_CHAIN && blk != 0; guard++) {
        ret = aleqfs_dev_read(dev, blk, buf);
        if (ret < 0)
            return found > 0 ? found : ret;

        uint16_t ns = node_num_slots(node);
        for (uint16_t i = 0; i < ns; i++) {
            if (node->slots[i].key != 0 &&
                (node->slots[i].key & pattern) == pattern) {
                if (found < max_results)
                    results[found] = node->slots[i].value;
                found++;
            }
        }

        blk = node_next_safe(dev, node);
    }

    return found;
}
