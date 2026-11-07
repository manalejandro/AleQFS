#ifndef ALEQFS_LAYOUT_H
#define ALEQFS_LAYOUT_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stddef.h>
#define ALEQFS_ATTR __attribute__((packed))
#else
#include <stdint.h>
#include <stddef.h>
#define ALEQFS_ATTR __attribute__((packed))
#endif

#define ALEQFS_MAGIC           0x414C45514653ULL
#define ALEQFS_FS_VERSION      2
#define ALEQFS_BLOCK_SIZE      4096
#define ALEQFS_INODE_SIZE      256
#define ALEQFS_INODES_PER_BLK  (ALEQFS_BLOCK_SIZE / ALEQFS_INODE_SIZE)
#define ALEQFS_NR_EXTENTS      4
#define ALEQFS_MAX_NAME        255
#define ALEQFS_ROOT_INO        1
#define ALEQFS_JOURNAL_BLOCKS  16
#define ALEQFS_BITMAP_BLOCKS   4
#define ALEQFS_INODE_BLOCKS    64
#define ALEQFS_GROVER_SLOTS    1024
#define ALEQFS_AMPLITUDE_BITS  16

#define ALEQFS_OP_MIRROR     (1ULL << 0)
#define ALEQFS_OP_SYNC       (1ULL << 1)
#define ALEQFS_OP_COLLAPSE   (1ULL << 2)

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
} ALEQFS_ATTR;

struct aleqfs_extent {
    uint64_t start;
    uint64_t count;
} ALEQFS_ATTR;

struct aleqfs_amplitude {
    int16_t real;
    int16_t imag;
} ALEQFS_ATTR;

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
} ALEQFS_ATTR;

struct aleqfs_grover_slot {
    uint64_t key;
    uint64_t value;
    int16_t  amplitude_real;
    int16_t  amplitude_imag;
    uint16_t flags;
    uint8_t  padding[4];
} ALEQFS_ATTR;

struct aleqfs_grover_node {
    uint64_t parent;
    uint64_t next;
    uint16_t num_slots;
    uint8_t  padding[6];
    struct aleqfs_grover_slot slots[];
} ALEQFS_ATTR;

struct aleqfs_entanglement_record {
    uint64_t ino_a;
    uint64_t ino_b;
    uint64_t established;
    uint64_t ops;
    uint8_t  padding[40];
} ALEQFS_ATTR;

struct aleqfs_direntry {
    uint64_t ino;
    uint8_t  name_len;
    int16_t  amplitude_real;
    int16_t  amplitude_imag;
    uint8_t  name[];
} ALEQFS_ATTR;

#define ALEQFS_DIR_ENTRY_MIN (sizeof(struct aleqfs_direntry))
#define ALEQFS_DIR_ENTRY_MAX (ALEQFS_DIR_ENTRY_MIN + ALEQFS_MAX_NAME)

/* grover slot flags */
#define ALEQFS_GROVER_F_USED 0x0001u
#define ALEQFS_GROVER_F_TOMB 0x8000u /* deleted key (open-addressing tombstone) */

#define ALEQFS_GROVER_HEADER_SIZE offsetof(struct aleqfs_grover_node, slots)
#define ALEQFS_GROVER_SLOTS_PER_BLK \
    ((ALEQFS_BLOCK_SIZE - ALEQFS_GROVER_HEADER_SIZE) / sizeof(struct aleqfs_grover_slot))

#endif
