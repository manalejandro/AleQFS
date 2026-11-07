#include "aleqfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <time.h>
#include <stdint.h>

static void print_usage(const char *prog);
static void print_mkfs_help(void);
static int run_mount_aleqfs(int argc, char **argv);
static int cmd_format(int argc, char **argv);
static int cmd_mkfs(int argc, char **argv);
static int cmd_mount(int argc, char **argv);
static int cmd_ls(int argc, char **argv);
static int cmd_mkdir(int argc, char **argv);
static int cmd_rmdir(int argc, char **argv);
static int cmd_cp_in(int argc, char **argv);
static int cmd_cat(int argc, char **argv);
static int cmd_stat(int argc, char **argv);
static int cmd_mv(int argc, char **argv);
static int cmd_rm(int argc, char **argv);
static int cmd_create(int argc, char **argv);
static int cmd_tree(int argc, char **argv);
static int cmd_dump(int argc, char **argv);
static int cmd_entangle(int argc, char **argv);
static int cmd_observe(int argc, char **argv);
static int cmd_decohere(int argc, char **argv);
static int cmd_grover(int argc, char **argv);
static int cmd_qstatus(int argc, char **argv);

static bool is_invoked_as(const char *argv0, const char *name)
{
    const char *base = strrchr(argv0, '/');
    if (!base) base = argv0; else base++;
    return strcmp(base, name) == 0;
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static int open_image(struct aleqfs_dev *dev, const char *img)
{
    int ret = aleqfs_dev_open(dev, img, O_RDWR);
    if (ret) {
        fprintf(stderr, "open failed: %s\n", strerror(-ret));
        return ret;
    }
    ret = aleqfs_super_load(dev);
    if (ret) {
        fprintf(stderr, "load superblock failed: %s\n", strerror(-ret));
        aleqfs_dev_close(dev);
        return ret;
    }
    return 0;
}

static int parse_u64_strict(const char *s, uint64_t *out, int base)
{
    if (!s || !*s || *s == '-')
        return -1;
    errno = 0;
    char *end;
    unsigned long long v = strtoull(s, &end, base);
    if (errno != 0 || end == s || *end != '\0')
        return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_size_mb(const char *s, uint64_t *out_mb)
{
    uint64_t v;
    if (parse_u64_strict(s, &v, 10) != 0)
        return -1;
    /* ALEQFS_MAX_BLOCKS / 256: blocks per MiB = 1MiB / 4KiB = 256 */
    if (v == 0 || v > ALEQFS_MAX_BLOCKS / 256) {
        fprintf(stderr,
                "invalid size %llu MiB (supported range: 1..%llu MiB)\n",
                (unsigned long long)v,
                (unsigned long long)(ALEQFS_MAX_BLOCKS / 256));
        return -1;
    }
    *out_mb = v;
    return 0;
}

/* path used as grover key: drop leading slashes so /a/b and a/b match */
static const char *grover_path(const char *path)
{
    while (*path == '/')
        path++;
    return path;
}

static void grover_index(struct aleqfs_dev *dev, const char *path, uint64_t ino)
{
    if (dev->sb.grover_root == 0)
        return;
    const char *p = grover_path(path);
    if (!*p)
        return;
    aleqfs_grover_insert(dev, dev->sb.grover_root, aleqfs_grover_key(p),
                         ino, 32767, 0);
}

static void grover_unindex(struct aleqfs_dev *dev, const char *path)
{
    if (dev->sb.grover_root == 0)
        return;
    const char *p = grover_path(path);
    if (!*p)
        return;
    aleqfs_grover_delete(dev, dev->sb.grover_root, aleqfs_grover_key(p));
}

/*
 * Release all resources of an inode that is no longer reachable through
 * any directory entry: break entanglement, free data blocks, free inode.
 */
static int free_orphan(struct aleqfs_dev *dev, uint64_t ino,
                       const char *full_path)
{
    struct aleqfs_inode inode;
    memset(&inode, 0, sizeof(inode));
    int ret = aleqfs_inode_read(dev, ino, &inode);
    if (ret) return ret;

    if (inode.entanglement_partner != 0)
        aleqfs_entangle_break(dev, ino, inode.entanglement_partner);

    if (full_path)
        grover_unindex(dev, full_path);

    uint32_t ec = aleqfs_extent_count_safe(&inode);
    for (uint32_t i = 0; i < ec; i++)
        aleqfs_extent_free(dev, &inode.extents[i]);

    return aleqfs_inode_free(dev, ino);
}

/*
 * Unlink a file or empty directory: remove the entry, then release the
 * orphaned inode (blocks, grover key, entanglement).
 */
static int unlink_child(struct aleqfs_dev *dev, uint64_t parent_ino,
                        const char *name, uint64_t child_ino,
                        const char *full_path)
{
    int ret = aleqfs_dir_remove_entry(dev, parent_ino, name);
    if (ret) return ret;
    return free_orphan(dev, child_ino, full_path);
}

static void format_time(char *buf, size_t len, uint64_t t)
{
    time_t tt = (time_t)t;
    struct tm tm;
    if (localtime_r(&tt, &tm) == NULL) {
        snprintf(buf, len, "(invalid)");
        return;
    }
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
}

static void print_usage(const char *prog)
{
    printf("AleQFS — Adaptive Linux Efficient QUANTUM Filesystem v%d\n", ALEQFS_FS_VERSION);
    printf("Usage:\n");
    printf("  %s format <img> <size_mb>\n", prog);
    printf("  %s mkfs <device> [size_mb]\n", prog);
    printf("  %s ls [--collapse] <img> <path>\n", prog);
    printf("  %s mkdir <img> <path>\n", prog);
    printf("  %s rmdir <img> <path>\n", prog);
    printf("  %s cp-in <img> <src> <dst>\n", prog);
    printf("  %s cat <img> <path>\n", prog);
    printf("  %s stat <img> <path>\n", prog);
    printf("  %s mv <img> <src> <dst>\n", prog);
    printf("  %s rm <img> <path>\n", prog);
    printf("  %s create <img> <path>\n", prog);
    printf("  %s tree [--collapse] <img> <path>\n", prog);
    printf("  %s dump <img>\n", prog);
    printf("  %s entangle <img> <path_a> <path_b>\n", prog);
    printf("  %s observe <img> <path>\n", prog);
    printf("  %s decohere <img> <path>\n", prog);
    printf("  %s grover <img> <pattern>\n", prog);
    printf("  %s mount <img> <mountpoint>\n", prog);
    printf("  %s qstatus <img>\n", prog);
    printf("\nSymlink invocation:\n");
    printf("  mkfs.aleqfs <device> [size_mb]\n");
    printf("  mount.aleqfs <device> [<mountpoint>]\n");
}

static void print_mkfs_help(void)
{
    printf("Usage: mkfs.aleqfs [options] <device> [size_mb]\n");
    printf("Create an AleQFS filesystem on a device or image file.\n");
    printf("\nOptions:\n");
    printf("  -V              print version\n");
    printf("  -h, --help      display this help\n");
    printf("\nArguments:\n");
    printf("  device          path to block device or image file\n");
    printf("  size_mb         size in MiB (default: 64 for regular files)\n");
    printf("\nExamples:\n");
    printf("  mkfs.aleqfs /tmp/test.img 64\n");
    printf("  mkfs.aleqfs /dev/sdb1\n");
    printf("  aleqfs mkfs /tmp/test.img 64\n");
}

static int run_mount_aleqfs(int argc, char **argv)
{
    int probe_mode = 0;
    int arg_idx = 1;

    if (argc > 1 && strcmp(argv[1], "--probe") == 0) {
        probe_mode = 1;
        arg_idx = 2;
        if (argc < 3) return 1;
    }

    if (probe_mode) {
        const char *device = argv[arg_idx];
        uint64_t magic = 0;
        int fd = open(device, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 1;
        ssize_t n = read(fd, &magic, sizeof(magic));
        close(fd);
        if (n != (ssize_t)sizeof(magic))
            return 1;
        if (magic != ALEQFS_MAGIC)
            return 1;
        printf("ID_FS_TYPE=aleqfs\n");
        printf("ID_FS_VERSION=%d\n", ALEQFS_FS_VERSION);
        return 0;
    }

    return cmd_mount(argc, argv);
}

/* ------------------------------------------------------------------ */
/* format / mkfs / mount                                               */
/* ------------------------------------------------------------------ */

static int do_format(const char *path, uint64_t size_mb, const char *tool)
{
    int ret = aleqfs_dev_create(path, size_mb);
    if (ret) {
        fprintf(stderr, "%s: create failed: %s\n", tool, strerror(-ret));
        return 1;
    }

    struct aleqfs_dev dev;
    ret = aleqfs_dev_open(&dev, path, O_RDWR);
    if (ret) {
        fprintf(stderr, "%s: open failed: %s\n", tool, strerror(-ret));
        return 1;
    }

    uint64_t total_blocks = (size_mb * 1024ULL * 1024ULL) / ALEQFS_BLOCK_SIZE;
    ret = aleqfs_super_format(&dev, total_blocks);
    if (ret) {
        fprintf(stderr, "%s: format failed: %s\n", tool, strerror(-ret));
        aleqfs_dev_close(&dev);
        return 1;
    }

    aleqfs_dev_close(&dev);
    printf("%s: formatted %s: %lu MiB (%lu blocks)\n", tool, path,
           (unsigned long)size_mb, (unsigned long)total_blocks);
    return 0;
}

static int cmd_format(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs format <img> <size_mb>\n"); return 1; }
    const char *path = argv[2];
    uint64_t size_mb;
    if (parse_size_mb(argv[3], &size_mb) != 0) {
        fprintf(stderr, "invalid size\n");
        return 1;
    }
    return do_format(path, size_mb, "aleqfs");
}

static int cmd_mkfs(int argc, char **argv)
{
    int arg_offset = (is_invoked_as(argv[0], "mkfs.aleqfs")) ? 1 : 2;

    if (argc <= arg_offset) {
        print_mkfs_help();
        return 0;
    }

    if (strcmp(argv[arg_offset], "-V") == 0) {
        printf("mkfs.aleqfs v%d\n", ALEQFS_FS_VERSION);
        return 0;
    }
    if (strcmp(argv[arg_offset], "-h") == 0 ||
        strcmp(argv[arg_offset], "--help") == 0) {
        print_mkfs_help();
        return 0;
    }

    const char *device = argv[arg_offset];
    uint64_t size_mb = 0;

    if (argc > arg_offset + 1) {
        if (parse_size_mb(argv[arg_offset + 1], &size_mb) != 0)
            return 1;
    }

    if (size_mb == 0) {
        struct stat st;
        if (stat(device, &st) == 0) {
            if (S_ISREG(st.st_mode))
                size_mb = (uint64_t)st.st_size / (1024 * 1024);
            else if (S_ISBLK(st.st_mode)) {
                int fd = open(device, O_RDONLY | O_CLOEXEC);
                if (fd >= 0) {
                    off_t sz = lseek(fd, 0, SEEK_END);
                    if (sz > 0)
                        size_mb = (uint64_t)sz / (1024 * 1024);
                    close(fd);
                }
            }
        }
        if (size_mb == 0)
            size_mb = 64;
        if (size_mb > ALEQFS_MAX_BLOCKS / 256) {
            fprintf(stderr,
                    "mkfs.aleqfs: %s too large (max %llu MiB addressable)\n",
                    device,
                    (unsigned long long)(ALEQFS_MAX_BLOCKS / 256));
            return 1;
        }
    }

    return do_format(device, size_mb, "mkfs.aleqfs");
}

static int cmd_mount(int argc, char **argv)
{
    const char *img = NULL, *mnt = NULL, *fstype = "aleqfs";
    unsigned long mountflags = 0;

    /* Called as mount.aleqfs: argv = [prog, dev, mnt, -t, fstype, -o, opts] */
    /* Called as aleqfs mount: argv = [prog, mount, dev, mnt, -o, opts]     */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            fstype = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            i++;
            char *opts = strdup(argv[i]);
            if (!opts) return 1;
            for (char *tok = strtok(opts, ","); tok; tok = strtok(NULL, ",")) {
                if (strcmp(tok, "ro") == 0) mountflags |= MS_RDONLY;
                else if (strcmp(tok, "noexec") == 0) mountflags |= MS_NOEXEC;
                else if (strcmp(tok, "nosuid") == 0) mountflags |= MS_NOSUID;
                else if (strcmp(tok, "nodev") == 0) mountflags |= MS_NODEV;
            }
            free(opts);
        } else if (argv[i][0] == '/') {
            if (!img) img = argv[i];
            else if (!mnt) mnt = argv[i];
        }
    }

    if (!img) {
        fprintf(stderr, "usage: mount.aleqfs <img> [<mountpoint>] [-o options]\n");
        fprintf(stderr, "       aleqfs mount <img> <mountpoint>\n");
        return 1;
    }

    char auto_mnt[PATH_MAX];
    if (!mnt) {
        /* udev/single-argument invocation: pick a stable automount point */
        const char *base = strrchr(img, '/');
        base = (base && base[1]) ? base + 1 : img;
        if (snprintf(auto_mnt, sizeof(auto_mnt), "/media/aleqfs/%s", base) >=
            (int)sizeof(auto_mnt)) {
            fprintf(stderr, "mount: device name too long\n");
            return 1;
        }
        mkdir("/media/aleqfs", 0755);
        if (mkdir(auto_mnt, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "mount: cannot create %s: %s\n", auto_mnt,
                    strerror(errno));
            return 1;
        }
        mnt = auto_mnt;
    }

    if (access(mnt, F_OK) != 0) {
        fprintf(stderr, "mount: %s does not exist (create it first)\n", mnt);
        return 1;
    }

    if (mount(img, mnt, fstype, mountflags, NULL) != 0) {
        fprintf(stderr, "mount: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* read commands                                                       */
/* ------------------------------------------------------------------ */

static int cmd_ls(int argc, char **argv)
{
    int idx = 2;
    bool collapse = false;

    if (argc > idx && strcmp(argv[idx], "--collapse") == 0) {
        collapse = true;
        idx++;
    }

    if (argc < idx + 2) { fprintf(stderr, "usage: aleqfs ls [--collapse] <img> <path>\n"); return 1; }
    const char *img = argv[idx];
    const char *path = argv[idx + 1];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t dir_ino;
    ret = aleqfs_path_resolve_full(&dev, path, &dir_ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    ret = aleqfs_dir_list(&dev, dir_ino, true, collapse);
    if (ret) { fprintf(stderr, "list failed: %s\n", strerror(-ret)); }

    aleqfs_dev_close(&dev);
    return ret ? 1 : 0;
}

static int cmd_cat(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs cat <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t ino;
    ret = aleqfs_path_resolve_full(&dev, path, &ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (!S_ISREG(inode.mode)) {
        fprintf(stderr, "cat: not a regular file\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    if (inode.size > dev.sb.total_blocks * (uint64_t)ALEQFS_BLOCK_SIZE) {
        fprintf(stderr, "cat: corrupt size (%lu bytes exceeds image capacity)\n",
                (unsigned long)inode.size);
        aleqfs_dev_close(&dev);
        return 1;
    }

    uint8_t *buf = malloc(inode.size > 0 ? inode.size : 1);
    if (!buf) { aleqfs_dev_close(&dev); fprintf(stderr, "cat: out of memory\n"); return 1; }

    ret = aleqfs_extent_read(&dev, &inode, 0, buf, inode.size);
    if (ret < 0) { free(buf); aleqfs_dev_close(&dev); fprintf(stderr, "read failed: %s\n", strerror(-ret)); return 1; }

    fwrite(buf, 1, inode.size, stdout);
    free(buf);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_stat(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs stat <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t ino;
    ret = aleqfs_path_resolve_full(&dev, path, &ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    char mode_str[11] = "----------";
    if (S_ISDIR(inode.mode)) mode_str[0] = 'd';
    else if (S_ISREG(inode.mode)) mode_str[0] = '-';
    if (inode.mode & S_IRUSR) mode_str[1] = 'r';
    if (inode.mode & S_IWUSR) mode_str[2] = 'w';
    if (inode.mode & S_IXUSR) mode_str[3] = 'x';
    if (inode.mode & S_IRGRP) mode_str[4] = 'r';
    if (inode.mode & S_IWGRP) mode_str[5] = 'w';
    if (inode.mode & S_IXGRP) mode_str[6] = 'x';
    if (inode.mode & S_IROTH) mode_str[7] = 'r';
    if (inode.mode & S_IWOTH) mode_str[8] = 'w';
    if (inode.mode & S_IXOTH) mode_str[9] = 'x';

    char atime_buf[64], mtime_buf[64], ctime_buf[64];
    format_time(atime_buf, sizeof(atime_buf), inode.atime);
    format_time(mtime_buf, sizeof(mtime_buf), inode.mtime);
    format_time(ctime_buf, sizeof(ctime_buf), inode.ctime);

    double prob = aleqfs_amplitude_probability(inode.amplitude.real, inode.amplitude.imag);

    printf("  File: %s\n", path);
    printf("  Inode: %lu\n", (unsigned long)ino);
    printf("  Size: %lu\n", (unsigned long)inode.size);
    printf("  Blocks: %lu\n", (unsigned long)inode.blocks);
    printf("  Mode: %s (%04o)\n", mode_str, inode.mode & 07777);
    printf("  UID: %u  GID: %u\n", inode.uid, inode.gid);
    printf("  Links: %u\n", inode.links);
    printf("  Access: %s\n", atime_buf);
    printf("  Modify: %s\n", mtime_buf);
    printf("  Change: %s\n", ctime_buf);
    uint32_t ec = aleqfs_extent_count_safe(&inode);
    printf("  Extents: %u\n", ec);
    for (uint32_t i = 0; i < ec; i++)
        printf("    [%u] block=%lu count=%lu\n",
               i, (unsigned long)inode.extents[i].start,
               (unsigned long)inode.extents[i].count);
    printf("  Quantum Amplitude: (%d, %d)\n", inode.amplitude.real, inode.amplitude.imag);
    printf("  Quantum Probability: %.6f\n", prob);
    printf("  Entanglement Partner: %lu\n", (unsigned long)inode.entanglement_partner);
    printf("  Observe Count: %u\n", inode.observe_count);

    /* decoherence detection on the first sealed data block */
    if (inode.size > 0 && ec > 0 && aleqfs_extent_sane(&dev, &inode.extents[0])) {
        uint8_t bbuf[ALEQFS_BLOCK_SIZE];
        if (aleqfs_dev_read(&dev, inode.extents[0].start, bbuf) == 0) {
            uint64_t cs = aleqfs_checksum(bbuf, sizeof(bbuf));
            if (inode.decoherence_stamp == 0)
                printf("  Coherence: unsealed\n");
            else if (cs == inode.decoherence_stamp)
                printf("  Coherence: coherent\n");
            else
                printf("  Coherence: DECOHERENT (block checksum mismatch)\n");
        }
    }

    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_tree(int argc, char **argv)
{
    int idx = 2;
    bool collapse = false;

    if (argc > idx && strcmp(argv[idx], "--collapse") == 0) {
        collapse = true;
        idx++;
    }

    if (argc < idx + 2) { fprintf(stderr, "usage: aleqfs tree [--collapse] <img> <path>\n"); return 1; }
    const char *img = argv[idx];
    const char *path = argv[idx + 1];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t dir_ino;
    ret = aleqfs_path_resolve_full(&dev, path, &dir_ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    printf("%s\n", path);
    ret = aleqfs_dir_tree(&dev, dir_ino, 0, path, collapse);
    if (ret) { fprintf(stderr, "tree failed: %s\n", strerror(-ret)); }

    aleqfs_dev_close(&dev);
    return ret ? 1 : 0;
}

static int cmd_dump(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: aleqfs dump <img>\n"); return 1; }
    const char *img = argv[2];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    struct aleqfs_superblock *sb = &dev.sb;
    printf("AleQFS Superblock Dump\n");
    printf("  Magic:             0x%016llX\n", (unsigned long long)sb->magic);
    printf("  Version:           %u\n", sb->version);
    printf("  Block Size:        %u\n", sb->block_size);
    printf("  Total Blocks:      %lu\n", (unsigned long)sb->total_blocks);
    printf("  Total Size:        %lu MiB\n",
           (unsigned long)(sb->total_blocks * sb->block_size / (1024*1024)));
    printf("  Inode Count:       %lu\n", (unsigned long)sb->inode_count);
    printf("  Free Inodes:       %lu\n", (unsigned long)sb->free_inodes);
    printf("  Free Blocks:       %lu\n", (unsigned long)sb->free_blocks);
    printf("  Root Inode:        %lu\n", (unsigned long)sb->root_inode);
    printf("  Journal:           block=%lu count=%lu\n",
           (unsigned long)sb->journal_start, (unsigned long)sb->journal_blocks);
    printf("  Grover Root:       block=%lu\n", (unsigned long)sb->grover_root);
    printf("  Inode Table:       block=%lu\n", (unsigned long)sb->inode_table_start);
    printf("  Bitmap:            block=%lu\n", (unsigned long)sb->bitmap_start);
    printf("  Data Start:        block=%lu\n", (unsigned long)sb->data_start);
    printf("  Entanglement:      block=%lu count=%lu\n",
           (unsigned long)sb->entanglement_start,
           (unsigned long)sb->entanglement_blocks);
    printf("  Features:          0x%016llX\n", (unsigned long long)sb->features);
    printf("  Quantum Temp:      %.2f\n", sb->quantum_temperature);
    printf("  Decoherence Rate:  %.6f\n", sb->decoherence_rate);
    printf("  Checksum:          0x%016llX (%s)\n",
           (unsigned long long)sb->checksum,
           sb->checksum == 0
               ? "not sealed (legacy image, sealed on next write)"
               : (sb->checksum == aleqfs_super_seal(sb) ? "valid" : "INVALID"));

    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_qstatus(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: aleqfs qstatus <img>\n"); return 1; }
    const char *img = argv[2];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t entanglement_count = 0;
    uint8_t buf[ALEQFS_BLOCK_SIZE];
    uint64_t start = dev.sb.entanglement_start;

    if (dev.sb.entanglement_blocks > 0 && dev.sb.entanglement_blocks <= 64 &&
        aleqfs_block_sane(&dev, start)) {
        for (uint64_t b = 0; b < dev.sb.entanglement_blocks; b++) {
            ret = aleqfs_dev_read(&dev, start + b, buf);
            if (ret < 0) break;
            struct aleqfs_entanglement_record *recs = (struct aleqfs_entanglement_record *)buf;
            uint64_t recs_per_blk = ALEQFS_BLOCK_SIZE / sizeof(struct aleqfs_entanglement_record);
            for (uint64_t i = 0; i < recs_per_blk; i++) {
                if (recs[i].ino_a != 0 || recs[i].ino_b != 0)
                    entanglement_count++;
            }
        }
    }

    /* count grover index entries (files/dirs known to the quantum search) */
    int grover_entries = 0;
    if (dev.sb.grover_root != 0) {
        uint64_t results[256];
        grover_entries = aleqfs_grover_search(&dev, dev.sb.grover_root, 0,
                                              results, 256);
        if (grover_entries < 0)
            grover_entries = 0;
    }

    printf("AleQFS Quantum System Status\n");
    printf("  Quantum Temperature:  %.2f\n", dev.sb.quantum_temperature);
    printf("  Decoherence Rate:     %.6f\n", dev.sb.decoherence_rate);
    printf("  Entanglement Count:   %lu\n", (unsigned long)entanglement_count);
    printf("  Grover Root Block:    %lu\n", (unsigned long)dev.sb.grover_root);
    printf("  Grover Index Entries: %d%s\n", grover_entries,
           grover_entries >= 256 ? "+" : "");
    printf("  Total Inodes:         %lu\n", (unsigned long)dev.sb.inode_count);
    printf("  Free Inodes:          %lu\n", (unsigned long)dev.sb.free_inodes);
    printf("  Free Blocks:          %lu\n", (unsigned long)dev.sb.free_blocks);

    aleqfs_dev_close(&dev);
    return 0;
}

/* ------------------------------------------------------------------ */
/* mutating commands                                                   */
/* ------------------------------------------------------------------ */

static int cmd_mkdir(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs mkdir <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    char name[ALEQFS_MAX_NAME + 1];
    uint64_t parent;
    ret = aleqfs_path_resolve(&dev, path, &parent, name);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (name[0] == '\0') { fprintf(stderr, "mkdir: cannot create root\n"); aleqfs_dev_close(&dev); return 1; }

    uint64_t ino;
    ret = aleqfs_dir_create(&dev, parent, name, S_IFDIR | 0755, &ino);
    if (ret == -EEXIST) {
        fprintf(stderr, "mkdir: cannot create '%s': File exists\n", path);
        aleqfs_dev_close(&dev);
        return 1;
    }
    if (ret) { fprintf(stderr, "mkdir failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    grover_index(&dev, path, ino);

    printf("Created directory: %s (ino=%lu)\n", path, (unsigned long)ino);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_create(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs create <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    char name[ALEQFS_MAX_NAME + 1];
    uint64_t parent;
    ret = aleqfs_path_resolve(&dev, path, &parent, name);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (name[0] == '\0') { fprintf(stderr, "create: invalid path\n"); aleqfs_dev_close(&dev); return 1; }

    uint64_t ino;
    ret = aleqfs_dir_create(&dev, parent, name, S_IFREG | 0644, &ino);
    if (ret == -EEXIST) {
        fprintf(stderr, "create: cannot create '%s': File exists\n", path);
        aleqfs_dev_close(&dev);
        return 1;
    }
    if (ret) { fprintf(stderr, "create failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    grover_index(&dev, path, ino);

    printf("Created empty file: %s (ino=%lu)\n", path, (unsigned long)ino);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_rmdir(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs rmdir <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    if (strcmp(path, "/") == 0) {
        fprintf(stderr, "rmdir: cannot remove root\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    char name[ALEQFS_MAX_NAME + 1];
    uint64_t parent;
    ret = aleqfs_path_resolve(&dev, path, &parent, name);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }
    if (name[0] == '\0') { fprintf(stderr, "rmdir: cannot remove root\n"); aleqfs_dev_close(&dev); return 1; }

    uint64_t child_ino;
    ret = aleqfs_dir_lookup(&dev, parent, name, &child_ino);
    if (ret) { fprintf(stderr, "lookup failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, child_ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (!S_ISDIR(inode.mode)) {
        fprintf(stderr, "rmdir: not a directory\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    bool empty = false;
    ret = aleqfs_dir_is_empty(&dev, child_ino, &empty);
    if (ret) { fprintf(stderr, "rmdir: check failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }
    if (!empty) {
        fprintf(stderr, "rmdir: failed to remove '%s': Directory not empty\n", path);
        aleqfs_dev_close(&dev);
        return 1;
    }

    ret = unlink_child(&dev, parent, name, child_ino, path);
    if (ret) { fprintf(stderr, "remove failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    /* parent loses one subdirectory link */
    struct aleqfs_inode pinode;
    if (aleqfs_inode_read(&dev, parent, &pinode) == 0 && pinode.links > 2) {
        pinode.links--;
        pinode.mtime = time(NULL);
        aleqfs_inode_write(&dev, parent, &pinode);
    }

    printf("Removed directory: %s\n", path);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_rm(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs rm <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    if (strcmp(path, "/") == 0) {
        fprintf(stderr, "rm: cannot remove root\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    char name[ALEQFS_MAX_NAME + 1];
    uint64_t parent;
    ret = aleqfs_path_resolve(&dev, path, &parent, name);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }
    if (name[0] == '\0') { fprintf(stderr, "rm: cannot remove root\n"); aleqfs_dev_close(&dev); return 1; }

    uint64_t child_ino;
    ret = aleqfs_dir_lookup(&dev, parent, name, &child_ino);
    if (ret) { fprintf(stderr, "lookup failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, child_ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (S_ISDIR(inode.mode)) {
        fprintf(stderr, "rm: is a directory, use rmdir\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    ret = unlink_child(&dev, parent, name, child_ino, path);
    if (ret) { fprintf(stderr, "remove failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    printf("Removed: %s\n", path);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_cp_in(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: aleqfs cp-in <img> <src> <dst>\n"); return 1; }
    const char *img = argv[2];
    const char *src_path = argv[3];
    const char *dst_path = argv[4];

    struct stat st;
    if (stat(src_path, &st) != 0) {
        fprintf(stderr, "open src failed: %s\n", strerror(errno));
        return 1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "cp-in: source %s is not a regular file\n", src_path);
        return 1;
    }
    uint64_t file_size = (uint64_t)st.st_size;

    FILE *src = fopen(src_path, "rb");
    if (!src) { fprintf(stderr, "open src failed: %s\n", strerror(errno)); return 1; }

    uint8_t *data = malloc(file_size > 0 ? file_size : 1);
    if (!data) { fclose(src); fprintf(stderr, "malloc failed\n"); return 1; }

    size_t nread = file_size > 0 ? fread(data, 1, file_size, src) : 0;
    fclose(src);
    if (nread != file_size) {
        free(data);
        fprintf(stderr, "cp-in: short read on %s\n", src_path);
        return 1;
    }

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) { free(data); return 1; }

    char name[ALEQFS_MAX_NAME + 1];
    uint64_t parent;
    ret = aleqfs_path_resolve(&dev, dst_path, &parent, name);
    if (ret) { free(data); aleqfs_dev_close(&dev); fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); return 1; }
    if (name[0] == '\0') { free(data); aleqfs_dev_close(&dev); fprintf(stderr, "cp-in: invalid destination\n"); return 1; }

    /* cp semantics: an existing destination is replaced atomically-ish */
    uint64_t old_ino;
    if (aleqfs_dir_lookup(&dev, parent, name, &old_ino) == 0) {
        struct aleqfs_inode old;
        if (aleqfs_inode_read(&dev, old_ino, &old) == 0 && S_ISDIR(old.mode)) {
            free(data);
            aleqfs_dev_close(&dev);
            fprintf(stderr, "cp-in: destination %s is a directory\n", dst_path);
            return 1;
        }
        ret = unlink_child(&dev, parent, name, old_ino, dst_path);
        if (ret) { free(data); aleqfs_dev_close(&dev); fprintf(stderr, "replace failed: %s\n", strerror(-ret)); return 1; }
    }

    uint64_t ino;
    ret = aleqfs_dir_create(&dev, parent, name, S_IFREG | 0644, &ino);
    if (ret) { free(data); aleqfs_dev_close(&dev); fprintf(stderr, "create file failed: %s\n", strerror(-ret)); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, ino, &inode);
    if (ret) {
        unlink_child(&dev, parent, name, ino, dst_path);
        free(data);
        aleqfs_dev_close(&dev);
        fprintf(stderr, "read inode failed: %s\n", strerror(-ret));
        return 1;
    }

    uint64_t written = 0;
    ret = aleqfs_extent_append(&dev, &inode, data, nread, &written, ino);
    free(data);
    if (ret || written != nread) {
        fprintf(stderr, "write failed: %s (wrote %llu of %llu bytes)\n",
                ret ? strerror(-ret) : "short write",
                (unsigned long long)written, (unsigned long long)nread);
        /* do not leave a half-written file behind */
        unlink_child(&dev, parent, name, ino, dst_path);
        aleqfs_dev_close(&dev);
        return 1;
    }

    grover_index(&dev, dst_path, ino);

    printf("Copied %zu bytes to %s (ino=%lu)\n", nread, dst_path, (unsigned long)ino);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_mv(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: aleqfs mv <img> <src> <dst>\n"); return 1; }
    const char *img = argv[2];
    const char *src_path = argv[3];
    const char *dst_path = argv[4];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    char src_name[ALEQFS_MAX_NAME + 1];
    uint64_t src_parent;
    ret = aleqfs_path_resolve(&dev, src_path, &src_parent, src_name);
    if (ret) { fprintf(stderr, "src resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }
    if (src_name[0] == '\0') { fprintf(stderr, "mv: cannot move root\n"); aleqfs_dev_close(&dev); return 1; }

    uint64_t child_ino;
    ret = aleqfs_dir_lookup(&dev, src_parent, src_name, &child_ino);
    if (ret) { fprintf(stderr, "src lookup failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    /* resolve the destination BEFORE touching the source */
    char dst_name[ALEQFS_MAX_NAME + 1];
    uint64_t dst_parent;
    ret = aleqfs_path_resolve(&dev, dst_path, &dst_parent, dst_name);
    if (ret) { fprintf(stderr, "dst resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }
    if (dst_name[0] == '\0') { fprintf(stderr, "mv: invalid destination\n"); aleqfs_dev_close(&dev); return 1; }

    if (src_parent == dst_parent && strcmp(src_name, dst_name) == 0) {
        aleqfs_dev_close(&dev);
        return 0; /* rename to self: no-op, like POSIX */
    }

    struct aleqfs_inode child_inode;
    ret = aleqfs_inode_read(&dev, child_ino, &child_inode);
    if (ret) { fprintf(stderr, "read child inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    uint64_t dst_ino;
    bool dst_exists = (aleqfs_dir_lookup(&dev, dst_parent, dst_name, &dst_ino) == 0);

    if (dst_exists && dst_ino == child_ino) {
        aleqfs_dev_close(&dev);
        return 0;
    }

    if (dst_exists) {
        struct aleqfs_inode dst_inode;
        if (aleqfs_inode_read(&dev, dst_ino, &dst_inode) == 0) {
            if (S_ISDIR(child_inode.mode) && !S_ISDIR(dst_inode.mode)) {
                fprintf(stderr, "mv: cannot overwrite non-directory %s with a directory\n", dst_path);
                aleqfs_dev_close(&dev);
                return 1;
            }
            if (!S_ISDIR(child_inode.mode) && S_ISDIR(dst_inode.mode)) {
                fprintf(stderr, "mv: cannot overwrite directory %s with a non-directory\n", dst_path);
                aleqfs_dev_close(&dev);
                return 1;
            }
        }
    }

    if (S_ISDIR(child_inode.mode) && dst_exists) {
        bool empty = false;
        aleqfs_dir_is_empty(&dev, dst_ino, &empty);
        if (!empty) {
            fprintf(stderr, "mv: cannot overwrite non-empty directory %s\n", dst_path);
            aleqfs_dev_close(&dev);
            return 1;
        }
    }

    uint8_t ft = S_ISDIR(child_inode.mode) ? ALEQFS_FT_DIR : ALEQFS_FT_FILE;

    /*
     * Add the destination entry first: dir_add_entry atomically replaces an
     * existing entry with the same name, so the child inode is never
     * unreachable. The source entry is only removed afterwards.
     */
    ret = aleqfs_dir_add_entry(&dev, dst_parent, child_ino, dst_name, ft);
    if (ret) { fprintf(stderr, "add entry failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    ret = aleqfs_dir_remove_entry(&dev, src_parent, src_name);
    if (ret) {
        /* extremely unlikely: the name now exists in both directories */
        fprintf(stderr, "warning: could not remove source entry: %s\n",
                strerror(-ret));
    }

    /* release the inode that was replaced at the destination, if any */
    if (dst_exists)
        free_orphan(&dev, dst_ino, NULL);

    /* keep directory link counts roughly POSIX-consistent */
    if (S_ISDIR(child_inode.mode) && src_parent != dst_parent) {
        struct aleqfs_inode p;
        if (aleqfs_inode_read(&dev, src_parent, &p) == 0 && p.links > 2) {
            p.links--;
            aleqfs_inode_write(&dev, src_parent, &p);
        }
        if (aleqfs_inode_read(&dev, dst_parent, &p) == 0) {
            p.links++;
            aleqfs_inode_write(&dev, dst_parent, &p);
        }
    }

    grover_unindex(&dev, src_path);
    grover_index(&dev, dst_path, child_ino);

    printf("Moved: %s -> %s\n", src_path, dst_path);
    aleqfs_dev_close(&dev);
    return 0;
}

/* ------------------------------------------------------------------ */
/* quantum commands                                                    */
/* ------------------------------------------------------------------ */

static int cmd_entangle(int argc, char **argv)
{
    if (argc < 5) { fprintf(stderr, "usage: aleqfs entangle <img> <path_a> <path_b>\n"); return 1; }
    const char *img = argv[2];
    const char *path_a = argv[3];
    const char *path_b = argv[4];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t ino_a, ino_b;
    ret = aleqfs_path_resolve_full(&dev, path_a, &ino_a);
    if (ret) { fprintf(stderr, "resolve %s failed: %s\n", path_a, strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    ret = aleqfs_path_resolve_full(&dev, path_b, &ino_b);
    if (ret) { fprintf(stderr, "resolve %s failed: %s\n", path_b, strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    if (ino_a == ino_b) {
        fprintf(stderr, "entangle: a directory cannot be entangled with itself\n");
        aleqfs_dev_close(&dev);
        return 1;
    }

    ret = aleqfs_entangle(&dev, ino_a, ino_b, ALEQFS_OP_MIRROR | ALEQFS_OP_SYNC);
    if (ret) { fprintf(stderr, "entangle failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    printf("Entanglement established: %lu <-> %lu\n",
           (unsigned long)ino_a, (unsigned long)ino_b);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_observe(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs observe <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t ino;
    ret = aleqfs_path_resolve_full(&dev, path, &ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    int16_t amp_real = inode.amplitude.real;
    int16_t amp_imag = inode.amplitude.imag;
    int collapsed = aleqfs_quantum_collapse(&amp_real, &amp_imag);
    inode.amplitude.real = amp_real;
    inode.amplitude.imag = amp_imag;

    inode.observe_count++;
    ret = aleqfs_inode_write(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "write inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    printf("Quantum state collapsed — file observed (%s).\n",
           collapsed ? "state survived" : "amplitude collapsed to zero");

    if (S_ISREG(inode.mode) && inode.size > 0 &&
        inode.size <= dev.sb.total_blocks * (uint64_t)ALEQFS_BLOCK_SIZE) {
        uint8_t *buf = malloc(inode.size);
        if (buf) {
            ret = aleqfs_extent_read(&dev, &inode, 0, buf, inode.size);
            if (ret >= 0)
                fwrite(buf, 1, inode.size, stdout);
            free(buf);
        }
    }

    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_decohere(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs decohere <img> <path>\n"); return 1; }
    const char *img = argv[2];
    const char *path = argv[3];

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    uint64_t ino;
    ret = aleqfs_path_resolve_full(&dev, path, &ino);
    if (ret) { fprintf(stderr, "path resolve failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    struct aleqfs_inode inode;
    ret = aleqfs_inode_read(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "read inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    inode.decoherence_stamp = ~inode.decoherence_stamp;

    ret = aleqfs_inode_write(&dev, ino, &inode);
    if (ret) { fprintf(stderr, "write inode failed: %s\n", strerror(-ret)); aleqfs_dev_close(&dev); return 1; }

    printf("Decoherence forced on inode %lu — coherence check will fail.\n",
           (unsigned long)ino);
    aleqfs_dev_close(&dev);
    return 0;
}

static int cmd_grover(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr, "usage: aleqfs grover <img> <pattern>\n"); return 1; }
    const char *img = argv[2];

    uint64_t pattern;
    if (parse_u64_strict(argv[3], &pattern, 0) != 0) {
        fprintf(stderr, "invalid pattern (use a number, e.g. 1 or 0xff)\n");
        return 1;
    }

    struct aleqfs_dev dev;
    int ret = open_image(&dev, img);
    if (ret) return 1;

    enum { MAX_RESULTS = 1024 };
    uint64_t results[MAX_RESULTS];
    int found = aleqfs_grover_search(&dev, dev.sb.grover_root, pattern,
                                     results, MAX_RESULTS);
    if (found < 0) { fprintf(stderr, "grover search failed: %s\n", strerror(-found)); aleqfs_dev_close(&dev); return 1; }

    int shown = found < MAX_RESULTS ? found : MAX_RESULTS;
    printf("Grover search for pattern 0x%llx found %d result(s):\n",
           (unsigned long long)pattern, found);
    for (int i = 0; i < shown; i++) {
        struct aleqfs_inode inode;
        if (aleqfs_inode_read(&dev, results[i], &inode) == 0 && inode.mode != 0) {
            printf("  ino=%lu size=%lu %s\n",
                   (unsigned long)results[i], (unsigned long)inode.size,
                   S_ISDIR(inode.mode) ? "(dir)" : "");
        }
    }

    aleqfs_dev_close(&dev);
    return 0;
}

int main(int argc, char **argv)
{
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    if (is_invoked_as(argv[0], "mkfs.aleqfs")) {
        argv[0] = (char *)"mkfs.aleqfs";
        return cmd_mkfs(argc, argv);
    }

    if (is_invoked_as(argv[0], "mount.aleqfs")) {
        argv[0] = (char *)"mount.aleqfs";
        return run_mount_aleqfs(argc, argv);
    }

    if (argc < 2) { print_usage(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "format") == 0)    return cmd_format(argc, argv);
    if (strcmp(cmd, "mkfs") == 0)      return cmd_mkfs(argc, argv);
    if (strcmp(cmd, "ls") == 0)        return cmd_ls(argc, argv);
    if (strcmp(cmd, "mkdir") == 0)     return cmd_mkdir(argc, argv);
    if (strcmp(cmd, "rmdir") == 0)     return cmd_rmdir(argc, argv);
    if (strcmp(cmd, "cp-in") == 0)     return cmd_cp_in(argc, argv);
    if (strcmp(cmd, "cat") == 0)       return cmd_cat(argc, argv);
    if (strcmp(cmd, "stat") == 0)      return cmd_stat(argc, argv);
    if (strcmp(cmd, "mv") == 0)        return cmd_mv(argc, argv);
    if (strcmp(cmd, "rm") == 0)        return cmd_rm(argc, argv);
    if (strcmp(cmd, "create") == 0)    return cmd_create(argc, argv);
    if (strcmp(cmd, "tree") == 0)      return cmd_tree(argc, argv);
    if (strcmp(cmd, "dump") == 0)      return cmd_dump(argc, argv);
    if (strcmp(cmd, "entangle") == 0)  return cmd_entangle(argc, argv);
    if (strcmp(cmd, "observe") == 0)   return cmd_observe(argc, argv);
    if (strcmp(cmd, "decohere") == 0)  return cmd_decohere(argc, argv);
    if (strcmp(cmd, "grover") == 0)    return cmd_grover(argc, argv);
    if (strcmp(cmd, "mount") == 0)     return cmd_mount(argc, argv);
    if (strcmp(cmd, "qstatus") == 0)   return cmd_qstatus(argc, argv);

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
