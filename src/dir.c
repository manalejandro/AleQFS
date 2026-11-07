#include "aleqfs.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

static unsigned int aleqfs_dentry_size(unsigned int name_len)
{
    return sizeof(struct aleqfs_direntry) + name_len;
}

/*
 * Directory blocks keep entries packed: the first slot with name_len == 0
 * terminates the used area. Removals compact the block so this invariant
 * holds (a zeroed slot in the middle would hide every entry after it).
 */
static int aleqfs_dir_find_in_block(const uint8_t *block, const char *name,
                                    unsigned int name_len, unsigned int *off_out)
{
    unsigned int off = 0;
    while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
        struct aleqfs_direntry *de = (struct aleqfs_direntry *)(block + off);
        if (de->name_len == 0) {
            *off_out = off;
            return -ENOENT;
        }
        unsigned int sz = aleqfs_dentry_size(de->name_len);
        if (off + sz > ALEQFS_BLOCK_SIZE)
            break;
        if (de->name_len == name_len &&
            memcmp(de->name, name, name_len) == 0)
            return (int)off;
        off += sz;
    }
    *off_out = ALEQFS_BLOCK_SIZE;
    return -ENOSPC;
}

static unsigned int aleqfs_dir_end_in_block(const uint8_t *block)
{
    unsigned int off = 0;
    while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
        struct aleqfs_direntry *de = (struct aleqfs_direntry *)(block + off);
        if (de->name_len == 0)
            return off;
        unsigned int sz = aleqfs_dentry_size(de->name_len);
        if (off + sz > ALEQFS_BLOCK_SIZE)
            return ALEQFS_BLOCK_SIZE;
        off += sz;
    }
    return ALEQFS_BLOCK_SIZE;
}

/* remove the entry at off by compacting the rest of the block forward */
static void aleqfs_dir_compact_entry(uint8_t *buf, unsigned int off,
                                     unsigned int sz)
{
    unsigned int end = aleqfs_dir_end_in_block(buf);
    if (end >= off + sz && end <= ALEQFS_BLOCK_SIZE) {
        memmove(buf + off, buf + off + sz, end - (off + sz));
        memset(buf + end - sz, 0, sz);
    } else {
        /* block already inconsistent (legacy hole): just zero the entry */
        memset(buf + off, 0, sz);
    }
}

int aleqfs_dir_lookup(struct aleqfs_dev *dev, uint64_t dir_ino,
                      const char *name, uint64_t *ino)
{
    struct aleqfs_inode dir_inode;
    int ret = aleqfs_inode_read(dev, dir_ino, &dir_inode);
    if (ret) return ret;
    if (!S_ISDIR(dir_inode.mode)) return -ENOTDIR;

    unsigned int name_len = strlen(name);
    if (name_len == 0 || name_len > ALEQFS_MAX_NAME) return -EINVAL;

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;

        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            ret = aleqfs_dev_read(dev, start + b, buf);
            if (ret) continue;

            unsigned int off;
            int found = aleqfs_dir_find_in_block(buf, name, name_len, &off);
            if (found >= 0) {
                struct aleqfs_direntry de;
                memcpy(&de, buf + found, sizeof(de));
                *ino = de.ino;
                return 0;
            }
        }
    }
    return -ENOENT;
}

int aleqfs_dir_add_entry(struct aleqfs_dev *dev, uint64_t dir_ino,
                         uint64_t child_ino, const char *name, uint8_t file_type)
{
    (void)file_type;
    unsigned int name_len = strlen(name);
    if (name_len == 0 || name_len > ALEQFS_MAX_NAME)
        return -EINVAL;

    struct aleqfs_inode dir_inode;
    int ret = aleqfs_inode_read(dev, dir_ino, &dir_inode);
    if (ret) return ret;
    if (!S_ISDIR(dir_inode.mode)) return -ENOTDIR;

    unsigned int esize = aleqfs_dentry_size(name_len);

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;

        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            ret = aleqfs_dev_read(dev, start + b, buf);
            if (ret) continue;

            unsigned int off;
            int found = aleqfs_dir_find_in_block(buf, name, name_len, &off);
            if (found >= 0) {
                struct aleqfs_direntry *de = (struct aleqfs_direntry *)(buf + found);
                de->ino = child_ino;
                return aleqfs_dev_write(dev, start + b, buf);
            }

            unsigned int end = aleqfs_dir_end_in_block(buf);
            if (end + esize <= ALEQFS_BLOCK_SIZE) {
                struct aleqfs_direntry *de = (struct aleqfs_direntry *)(buf + end);
                de->ino = child_ino;
                de->name_len = (uint8_t)name_len;
                de->amplitude_real = 32767;
                de->amplitude_imag = 0;
                memcpy(de->name, name, name_len);
                return aleqfs_dev_write(dev, start + b, buf);
            }
        }
    }

    uint64_t new_block;
    ret = aleqfs_bitmap_alloc(dev, &new_block);
    if (ret) return ret;

    /* make room in the extent list before touching the disk layout */
    if (dir_inode.extent_count >= ALEQFS_NR_EXTENTS) {
        struct aleqfs_extent *last = &dir_inode.extents[ALEQFS_NR_EXTENTS - 1];
        if (!(aleqfs_extent_sane(dev, last) &&
              last->start + last->count == new_block)) {
            aleqfs_bitmap_free(dev, new_block);
            return -ENOSPC;
        }
    }

    uint8_t zbuf[ALEQFS_BLOCK_SIZE];
    memset(zbuf, 0, sizeof(zbuf));
    struct aleqfs_direntry *de = (struct aleqfs_direntry *)zbuf;
    de->ino = child_ino;
    de->name_len = (uint8_t)name_len;
    de->amplitude_real = 32767;
    de->amplitude_imag = 0;
    memcpy(de->name, name, name_len);
    ret = aleqfs_dev_write(dev, new_block, zbuf);
    if (ret) {
        aleqfs_bitmap_free(dev, new_block);
        return ret;
    }

    if (dir_inode.extent_count > 0) {
        uint32_t ecount = aleqfs_extent_count_safe(&dir_inode);
        struct aleqfs_extent *last = &dir_inode.extents[ecount - 1];
        if (aleqfs_extent_sane(dev, last) &&
            last->start + last->count == new_block) {
            last->count++;
        } else if (dir_inode.extent_count < ALEQFS_NR_EXTENTS) {
            dir_inode.extents[dir_inode.extent_count].start = new_block;
            dir_inode.extents[dir_inode.extent_count].count = 1;
            dir_inode.extent_count++;
        } else {
            aleqfs_bitmap_free(dev, new_block);
            return -ENOSPC;
        }
    } else {
        dir_inode.extents[0].start = new_block;
        dir_inode.extents[0].count = 1;
        dir_inode.extent_count = 1;
    }
    dir_inode.blocks = 0;
    for (uint32_t i = 0; i < aleqfs_extent_count_safe(&dir_inode); i++)
        dir_inode.blocks += dir_inode.extents[i].count;
    dir_inode.mtime = time(NULL);
    return aleqfs_inode_write(dev, dir_ino, &dir_inode);
}

int aleqfs_dir_remove_entry(struct aleqfs_dev *dev, uint64_t dir_ino,
                            const char *name)
{
    unsigned int name_len = strlen(name);
    if (name_len == 0 || name_len > ALEQFS_MAX_NAME) return -EINVAL;

    struct aleqfs_inode dir_inode;
    int ret = aleqfs_inode_read(dev, dir_ino, &dir_inode);
    if (ret) return ret;
    if (!S_ISDIR(dir_inode.mode)) return -ENOTDIR;

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;

        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            ret = aleqfs_dev_read(dev, start + b, buf);
            if (ret) continue;

            unsigned int off;
            int found = aleqfs_dir_find_in_block(buf, name, name_len, &off);
            if (found >= 0) {
                unsigned int sz = aleqfs_dentry_size(
                    ((struct aleqfs_direntry *)(buf + found))->name_len);
                aleqfs_dir_compact_entry(buf, (unsigned int)found, sz);
                ret = aleqfs_dev_write(dev, start + b, buf);
                if (ret) return ret;

                dir_inode.mtime = time(NULL);
                return aleqfs_inode_write(dev, dir_ino, &dir_inode);
            }
        }
    }
    return -ENOENT;
}

int aleqfs_dir_is_empty(struct aleqfs_dev *dev, uint64_t dir_ino, bool *empty)
{
    *empty = true;

    struct aleqfs_inode dir_inode;
    int ret = aleqfs_inode_read(dev, dir_ino, &dir_inode);
    if (ret) return ret;
    if (!S_ISDIR(dir_inode.mode)) return -ENOTDIR;

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec && *empty; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;

        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            if (aleqfs_dev_read(dev, start + b, buf))
                continue;
            if (aleqfs_dir_end_in_block(buf) != 0) {
                *empty = false;
                break;
            }
        }
    }
    return 0;
}

int aleqfs_dir_list(struct aleqfs_dev *dev, uint64_t dir_ino, bool show_all,
                    bool quantum_collapse)
{
    (void)show_all;
    struct aleqfs_inode dir_inode;
    int ret = aleqfs_inode_read(dev, dir_ino, &dir_inode);
    if (ret) return ret;
    if (!S_ISDIR(dir_inode.mode)) return -ENOTDIR;

    printf("total %lu\n", (unsigned long)dev->sb.total_blocks);

    double threshold = 0.0;
    if (quantum_collapse)
        threshold = (double)rand() / (double)RAND_MAX;

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;

        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            ret = aleqfs_dev_read(dev, start + b, buf);
            if (ret) continue;

            unsigned int off = 0;
            while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
                struct aleqfs_direntry *de = (struct aleqfs_direntry *)(buf + off);
                if (de->name_len == 0) break;
                unsigned int sz = aleqfs_dentry_size(de->name_len);
                if (off + sz > ALEQFS_BLOCK_SIZE) break;

                double prob = aleqfs_amplitude_probability(de->amplitude_real,
                                                           de->amplitude_imag);

                if (quantum_collapse && prob < threshold) {
                    off += sz;
                    continue;
                }

                printf("  %.*s  [%lu]  amp=(%4d,%4d)  p=%.3f\n",
                       (int)de->name_len, (const char *)de->name,
                       (unsigned long)de->ino,
                       de->amplitude_real, de->amplitude_imag, prob);
                off += sz;
            }
        }
    }
    return 0;
}

static void aleqfs_dir_tree_recursive(struct aleqfs_dev *dev, uint64_t dir_ino,
                                      int depth, bool quantum_collapse);

static void aleqfs_dir_tree_block(struct aleqfs_dev *dev, const uint8_t *buf,
                                  int depth, bool quantum_collapse)
{
    double threshold = 0.0;
    if (quantum_collapse)
        threshold = (double)rand() / (double)RAND_MAX;

    unsigned int off = 0;
    while (off + sizeof(struct aleqfs_direntry) <= ALEQFS_BLOCK_SIZE) {
        struct aleqfs_direntry *de = (struct aleqfs_direntry *)(buf + off);
        if (de->name_len == 0) break;
        unsigned int sz = aleqfs_dentry_size(de->name_len);
        if (off + sz > ALEQFS_BLOCK_SIZE) break;

        double prob = aleqfs_amplitude_probability(de->amplitude_real,
                                                   de->amplitude_imag);

        if (quantum_collapse && prob < threshold) {
            off += sz;
            continue;
        }

        for (int i = 0; i < depth; i++) printf("    ");

        struct aleqfs_inode child;
        bool is_dir = false;
        if (aleqfs_inode_read(dev, de->ino, &child) == 0 && child.mode != 0)
            is_dir = S_ISDIR(child.mode);

        if (quantum_collapse)
            printf("├── %.*s (ino=%lu) [p=%.3f]\n",
                   (int)de->name_len, (const char *)de->name,
                   (unsigned long)de->ino, prob);
        else
            printf("├── %.*s (ino=%lu)  amp=(%4d,%4d)  p=%.3f\n",
                   (int)de->name_len, (const char *)de->name,
                   (unsigned long)de->ino,
                   de->amplitude_real, de->amplitude_imag, prob);

        if (is_dir && depth + 1 < ALEQFS_TREE_MAX_DEPTH)
            aleqfs_dir_tree_recursive(dev, de->ino, depth + 1, quantum_collapse);

        off += sz;
    }
}

static void aleqfs_dir_tree_recursive(struct aleqfs_dev *dev, uint64_t dir_ino,
                                      int depth, bool quantum_collapse)
{
    if (depth >= ALEQFS_TREE_MAX_DEPTH)
        return;

    struct aleqfs_inode dir_inode;
    if (aleqfs_inode_read(dev, dir_ino, &dir_inode) != 0) return;
    if (!S_ISDIR(dir_inode.mode)) return;

    uint32_t ec = aleqfs_extent_count_safe(&dir_inode);
    for (uint32_t e = 0; e < ec; e++) {
        if (!aleqfs_extent_sane(dev, &dir_inode.extents[e]))
            continue;
        uint64_t start = dir_inode.extents[e].start;
        uint64_t count = dir_inode.extents[e].count;
        for (uint64_t b = 0; b < count; b++) {
            uint8_t buf[ALEQFS_BLOCK_SIZE];
            if (aleqfs_dev_read(dev, start + b, buf)) continue;
            aleqfs_dir_tree_block(dev, buf, depth, quantum_collapse);
        }
    }
}

int aleqfs_dir_tree(struct aleqfs_dev *dev, uint64_t dir_ino, int depth,
                    const char *path, bool quantum_collapse)
{
    (void)path;
    aleqfs_dir_tree_recursive(dev, dir_ino, depth, quantum_collapse);
    return 0;
}

int aleqfs_dir_create(struct aleqfs_dev *dev, uint64_t parent_ino,
                      const char *name, uint16_t mode, uint64_t *ino)
{
    struct aleqfs_inode parent;
    int ret = aleqfs_inode_read(dev, parent_ino, &parent);
    if (ret) return ret;
    if (!S_ISDIR(parent.mode)) return -ENOTDIR;

    /* refuse duplicates: silently replacing an entry orphans the old inode */
    uint64_t existing;
    if (aleqfs_dir_lookup(dev, parent_ino, name, &existing) == 0)
        return -EEXIST;

    uint64_t child_ino;
    ret = aleqfs_inode_alloc(dev, &child_ino);
    if (ret) return ret;

    struct aleqfs_inode child;
    memset(&child, 0, sizeof(child));
    child.mode   = mode;
    child.uid    = getuid();
    child.gid    = getgid();
    child.links  = S_ISDIR(mode) ? 2 : 1;
    child.atime  = child.mtime = child.ctime = time(NULL);
    child.amplitude.real = 32767;
    child.amplitude.imag = 0;

    ret = aleqfs_inode_write(dev, child_ino, &child);
    if (ret) {
        aleqfs_inode_free(dev, child_ino);
        return ret;
    }

    ret = aleqfs_dir_add_entry(dev, parent_ino, child_ino, name,
                               S_ISDIR(mode) ? ALEQFS_FT_DIR : ALEQFS_FT_FILE);
    if (ret) {
        aleqfs_inode_free(dev, child_ino);
        return ret;
    }

    if (S_ISDIR(mode)) {
        /* refresh parent: dir_add_entry may have rewritten it */
        if (aleqfs_inode_read(dev, parent_ino, &parent) == 0) {
            parent.links++;
            parent.mtime = time(NULL);
            aleqfs_inode_write(dev, parent_ino, &parent);
        }
    }

    *ino = child_ino;
    return 0;
}
