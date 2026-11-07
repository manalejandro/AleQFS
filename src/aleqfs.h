#ifndef ALEQFS_H
#define ALEQFS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define ALEQFS_MAGIC           0x414C45514653ULL
#define ALEQFS_FS_VERSION      2
#define ALEQFS_BLOCK_SIZE      4096
#define ALEQFS_BLOCK_SHIFT     12
#define ALEQFS_INODE_SIZE      256
#define ALEQFS_INODES_PER_BLK  (ALEQFS_BLOCK_SIZE / ALEQFS_INODE_SIZE)
#define ALEQFS_NR_EXTENTS      4
#define ALEQFS_MAX_NAME        255
#define ALEQFS_ROOT_INO        1
#define ALEQFS_JOURNAL_BLOCKS  16
#define ALEQFS_BITMAP_BLOCKS   4
#define ALEQFS_INODE_BLOCKS    64
#define ALEQFS_GROVER_SLOTS    1024

#define ALEQFS_OP_MIRROR     (1ULL << 0)
#define ALEQFS_OP_SYNC       (1ULL << 1)
#define ALEQFS_OP_COLLAPSE   (1ULL << 2)

/* grover slot flags */
#define ALEQFS_GROVER_F_USED 0x0001u
#define ALEQFS_GROVER_F_TOMB 0x8000u /* deleted key (open-addressing tombstone) */

/* recursion cap for tree walks (corrupt images may contain dir cycles) */
#define ALEQFS_TREE_MAX_DEPTH 64

/* the allocation bitmap caps the addressable fs size */
#define ALEQFS_MAX_BLOCKS ((uint64_t)ALEQFS_BITMAP_BLOCKS * ALEQFS_BLOCK_SIZE * 8)

/* minimum usable image: metadata + grover root + entanglement area + slack */
#define ALEQFS_MIN_DATA_BLOCKS 64

enum aleqfs_file_type {
    ALEQFS_FT_UNKNOWN,
    ALEQFS_FT_FILE,
    ALEQFS_FT_DIR,
    ALEQFS_FT_ENTANGLED,
    ALEQFS_FT_SUPERPOSED,
};

enum aleqfs_cmd {
    ALEQFS_CMD_FORMAT,
    ALEQFS_CMD_MKFS,
    ALEQFS_CMD_LS,
    ALEQFS_CMD_MKDIR,
    ALEQFS_CMD_RMDIR,
    ALEQFS_CMD_CP_IN,
    ALEQFS_CMD_CAT,
    ALEQFS_CMD_STAT,
    ALEQFS_CMD_MV,
    ALEQFS_CMD_RM,
    ALEQFS_CMD_CREATE,
    ALEQFS_CMD_TREE,
    ALEQFS_CMD_DUMP,
    ALEQFS_CMD_ENTANGLE,
    ALEQFS_CMD_OBSERVE,
    ALEQFS_CMD_DECOHERE,
    ALEQFS_CMD_GROVER,
    ALEQFS_CMD_QSTATUS,
};

struct aleqfs_superblock {
    uint64_t magic;
    uint32_t version;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t inode_count;
    uint64_t free_blocks;
    uint64_t free_inodes;
    uint64_t root_inode;
    uint64_t journal_start;
    uint64_t journal_blocks;
    uint64_t grover_root;
    uint64_t inode_table_start;
    uint64_t bitmap_start;
    uint64_t data_start;
    uint64_t features;
    double   quantum_temperature;
    double   decoherence_rate;
    uint64_t checksum;
    uint64_t entanglement_start;
    uint64_t entanglement_blocks;
    uint8_t  padding[3944];
} __attribute__((packed));

_Static_assert(sizeof(struct aleqfs_superblock) == ALEQFS_BLOCK_SIZE,
               "superblock must be exactly one block");

struct aleqfs_extent {
    uint64_t start;
    uint64_t count;
} __attribute__((packed));

struct aleqfs_amplitude {
    int16_t real;
    int16_t imag;
} __attribute__((packed));

struct aleqfs_inode {
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint16_t links;
    uint32_t flags;
    uint64_t size;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint64_t blocks;
    uint32_t extent_count;
    struct aleqfs_extent extents[ALEQFS_NR_EXTENTS];
    uint64_t entanglement_partner;
    uint64_t entanglement_ops;
    struct aleqfs_amplitude amplitude;
    uint64_t grover_hash;
    uint64_t decoherence_stamp;
    uint32_t observe_count;
    uint8_t  padding[96];
} __attribute__((packed));

_Static_assert(sizeof(struct aleqfs_inode) == ALEQFS_INODE_SIZE,
               "inode size must match ALEQFS_INODE_SIZE");

struct aleqfs_grover_slot {
    uint64_t key;
    uint64_t value;
    int16_t  amplitude_real;
    int16_t  amplitude_imag;
    uint16_t flags;
    uint8_t  padding[4];
} __attribute__((packed));

struct aleqfs_grover_node {
    uint64_t parent;
    uint64_t next;
    uint16_t num_slots;
    uint8_t  padding[6];
    struct aleqfs_grover_slot slots[];
} __attribute__((packed));

#define ALEQFS_GROVER_HEADER_SIZE offsetof(struct aleqfs_grover_node, slots)
#define ALEQFS_GROVER_SLOTS_PER_BLK ((ALEQFS_BLOCK_SIZE - ALEQFS_GROVER_HEADER_SIZE) / sizeof(struct aleqfs_grover_slot))

struct aleqfs_entanglement_record {
    uint64_t ino_a;
    uint64_t ino_b;
    uint64_t established;
    uint64_t ops;
    uint8_t  padding[40];
} __attribute__((packed));

struct aleqfs_direntry {
    uint64_t ino;
    uint8_t  name_len;
    int16_t  amplitude_real;
    int16_t  amplitude_imag;
    uint8_t  name[];
} __attribute__((packed));

struct aleqfs_dev {
    int      fd;
    uint64_t num_blocks;
    uint64_t block_size;
    char    *path;
    struct aleqfs_superblock sb;
    bool     dirty;
};

/*
 * An extent is sane only if it lies entirely inside the data area of this
 * device. Corrupt extents (pointing at the superblock, bitmap, inode table
 * or past EOF) must never be read from or written to.
 */
static inline bool aleqfs_extent_sane(const struct aleqfs_dev *dev,
                                      const struct aleqfs_extent *e)
{
    if (e->count == 0)
        return false;
    if (dev->sb.total_blocks == 0 || e->start < dev->sb.data_start)
        return false;
    if (e->count > dev->sb.total_blocks)
        return false;
    return e->start + e->count <= dev->sb.total_blocks;
}

static inline bool aleqfs_block_sane(const struct aleqfs_dev *dev, uint64_t blk)
{
    return blk >= dev->sb.data_start && blk < dev->sb.total_blocks;
}

#define ALEQFS_ASSERT(x) do { if (!(x)) { fprintf(stderr, "ALEQFS ASSERT: %s at %s:%d\n", #x, __FILE__, __LINE__); exit(1); } } while(0)

static inline double aleqfs_amplitude_probability(int16_t real, int16_t imag)
{
    return (real * real + imag * imag) / (double)(32767 * 32767);
}

static inline void aleqfs_amplitude_normalize(int16_t *real, int16_t *imag)
{
    double r = *real, i = *imag;
    double mag = sqrt(r * r + i * i);
    if (mag > 0) {
        *real = (int16_t)(r / mag * 32767);
        *imag = (int16_t)(i / mag * 32767);
    } else {
        *real = 32767;
        *imag = 0;
    }
}

/*
 * On-disk data may be corrupt or hostile: never trust extent_count or
 * extent ranges read from an image. These helpers clamp/sanitize them so
 * loops stay bounded and block numbers stay inside the data area.
 */
static inline uint32_t aleqfs_extent_count_safe(const struct aleqfs_inode *inode)
{
    return inode->extent_count > ALEQFS_NR_EXTENTS
               ? (uint32_t)ALEQFS_NR_EXTENTS
               : inode->extent_count;
}

/* superblock integrity seal (FNV-1a over the sb with checksum zeroed) */
uint64_t aleqfs_super_seal(const struct aleqfs_superblock *sb);

// io.c
int  aleqfs_dev_open(struct aleqfs_dev *dev, const char *path, int flags);
int  aleqfs_dev_close(struct aleqfs_dev *dev);
int  aleqfs_dev_read(struct aleqfs_dev *dev, uint64_t block, void *buf);
int  aleqfs_dev_write(struct aleqfs_dev *dev, uint64_t block, const void *buf);
int  aleqfs_dev_flush(struct aleqfs_dev *dev);
int  aleqfs_dev_sync(struct aleqfs_dev *dev);
int  aleqfs_dev_create(const char *path, uint64_t size_mb);

// super.c
int  aleqfs_super_format(struct aleqfs_dev *dev, uint64_t total_blocks);
int  aleqfs_super_load(struct aleqfs_dev *dev);
int  aleqfs_super_sync(struct aleqfs_dev *dev);

// bitmap.c
int  aleqfs_bitmap_init(struct aleqfs_dev *dev);
int  aleqfs_bitmap_alloc(struct aleqfs_dev *dev, uint64_t *block);
int  aleqfs_bitmap_free(struct aleqfs_dev *dev, uint64_t block);
void aleqfs_bitmark_set(struct aleqfs_dev *dev, uint64_t block);
bool aleqfs_bitmap_get(struct aleqfs_dev *dev, uint64_t block);

// inode.c
int  aleqfs_inode_alloc(struct aleqfs_dev *dev, uint64_t *ino);
int  aleqfs_inode_free(struct aleqfs_dev *dev, uint64_t ino);
int  aleqfs_inode_read(struct aleqfs_dev *dev, uint64_t ino, struct aleqfs_inode *inode);
int  aleqfs_inode_write(struct aleqfs_dev *dev, uint64_t ino, const struct aleqfs_inode *inode);

// extent.c
int  aleqfs_extent_alloc(struct aleqfs_dev *dev, uint64_t count, struct aleqfs_extent *ext);
int  aleqfs_extent_free(struct aleqfs_dev *dev, const struct aleqfs_extent *ext);
int  aleqfs_extent_read(struct aleqfs_dev *dev, const struct aleqfs_inode *inode,
                        uint64_t offset, void *buf, uint64_t size);
int  aleqfs_extent_write(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                         uint64_t offset, const void *buf, uint64_t size);
int  aleqfs_extent_append(struct aleqfs_dev *dev, struct aleqfs_inode *inode,
                          const void *buf, uint64_t size, uint64_t *bytes_written,
                          uint64_t ino);

// dir.c
int  aleqfs_dir_lookup(struct aleqfs_dev *dev, uint64_t dir_ino,
                       const char *name, uint64_t *ino);
int  aleqfs_dir_add_entry(struct aleqfs_dev *dev, uint64_t dir_ino,
                          uint64_t child_ino, const char *name, uint8_t file_type);
int  aleqfs_dir_remove_entry(struct aleqfs_dev *dev, uint64_t dir_ino,
                             const char *name);
int  aleqfs_dir_is_empty(struct aleqfs_dev *dev, uint64_t dir_ino, bool *empty);
int  aleqfs_dir_list(struct aleqfs_dev *dev, uint64_t dir_ino, bool show_all,
                     bool quantum_collapse);
int  aleqfs_dir_tree(struct aleqfs_dev *dev, uint64_t dir_ino, int depth,
                     const char *path, bool quantum_collapse);
int  aleqfs_dir_create(struct aleqfs_dev *dev, uint64_t parent_ino,
                       const char *name, uint16_t mode, uint64_t *ino);

// path.c
/* leaf must point to a buffer of at least ALEQFS_MAX_NAME + 1 bytes */
int  aleqfs_path_resolve(struct aleqfs_dev *dev, const char *path,
                         uint64_t *parent_ino, char *leaf);
int  aleqfs_path_resolve_full(struct aleqfs_dev *dev, const char *path,
                              uint64_t *ino);

// grover.c
uint64_t aleqfs_grover_key(const char *name);
int  aleqfs_grover_init(struct aleqfs_dev *dev, uint64_t *root_block);
int  aleqfs_grover_insert(struct aleqfs_dev *dev, uint64_t root_block,
                          uint64_t key, uint64_t value, int16_t amp_real, int16_t amp_imag);
int  aleqfs_grover_lookup(struct aleqfs_dev *dev, uint64_t root_block,
                          uint64_t key, uint64_t *value);
int  aleqfs_grover_delete(struct aleqfs_dev *dev, uint64_t root_block, uint64_t key);
int  aleqfs_grover_search(struct aleqfs_dev *dev, uint64_t root_block,
                          uint64_t pattern, uint64_t *results, int max_results);

// entangle.c
int  aleqfs_entangle(struct aleqfs_dev *dev, uint64_t ino_a, uint64_t ino_b, uint64_t ops);
int  aleqfs_entangle_break(struct aleqfs_dev *dev, uint64_t ino_a, uint64_t ino_b);
int  aleqfs_entangle_mirror(struct aleqfs_dev *dev, uint64_t src_ino,
                            uint64_t *mirror_ino);
int  aleqfs_entanglement_read(struct aleqfs_dev *dev, uint64_t ino,
                              struct aleqfs_entanglement_record *rec);

// checksum.c
uint64_t aleqfs_checksum(const void *data, size_t len);
int      aleqfs_decoherence_check(struct aleqfs_dev *dev, uint64_t block,
                                  uint64_t expected_checksum);

// quantum.c
double aleqfs_quantum_probability(int16_t real, int16_t imag);
int    aleqfs_quantum_collapse(int16_t *real, int16_t *imag);
int    aleqfs_quantum_entangle_state(struct aleqfs_dev *dev, uint64_t ino,
                                     struct aleqfs_inode *inode);
int    aleqfs_quantum_temperature(struct aleqfs_dev *dev);

// journal.c
int aleqfs_journal_recover(struct aleqfs_dev *dev);
int aleqfs_journal_record(struct aleqfs_dev *dev, uint64_t ino,
                           uint64_t block, uint64_t count);
int aleqfs_journal_extend(struct aleqfs_dev *dev, uint64_t ino,
                           uint64_t block, uint64_t count);
int aleqfs_journal_clear(struct aleqfs_dev *dev, uint64_t ino,
                          uint64_t block, uint64_t count);

#endif
