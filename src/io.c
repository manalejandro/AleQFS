#include "aleqfs.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

int aleqfs_dev_open(struct aleqfs_dev *dev, const char *path, int flags)
{
    struct stat st;
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;

    if (stat(path, &st) == 0 && S_ISBLK(st.st_mode)) {
        dev->fd = open(path, O_RDWR | O_CLOEXEC);
        if (dev->fd < 0)
            return -errno;
        off_t size = lseek(dev->fd, 0, SEEK_END);
        if (size < 0) {
            int e = errno;
            close(dev->fd);
            dev->fd = -1;
            return -e;
        }
        dev->num_blocks = (uint64_t)size / ALEQFS_BLOCK_SIZE;
    } else {
        dev->fd = open(path, flags | O_CLOEXEC, 0644);
        if (dev->fd < 0)
            return -errno;
        off_t size = lseek(dev->fd, 0, SEEK_END);
        if (size < 0) {
            int e = errno;
            close(dev->fd);
            dev->fd = -1;
            return -e;
        }
        dev->num_blocks = (uint64_t)size / ALEQFS_BLOCK_SIZE;
    }

    dev->path = strdup(path);
    dev->block_size = ALEQFS_BLOCK_SIZE;
    if (!dev->path) {
        close(dev->fd);
        dev->fd = -1;
        return -ENOMEM;
    }
    return 0;
}

int aleqfs_dev_close(struct aleqfs_dev *dev)
{
    if (dev->dirty)
        aleqfs_super_sync(dev);
    if (dev->fd >= 0)
        close(dev->fd);
    free(dev->path);
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;
    return 0;
}

int aleqfs_dev_read(struct aleqfs_dev *dev, uint64_t block, void *buf)
{
    if (dev->fd < 0)
        return -EBADF;
    /* num_blocks may legitimately be 0 while formatting a fresh device */
    if (dev->num_blocks && block >= dev->num_blocks)
        return -EIO;
    off_t offset = (off_t)block * (off_t)dev->block_size;
    ssize_t n = pread(dev->fd, buf, dev->block_size, offset);
    if (n != (ssize_t)dev->block_size)
        return -EIO;
    return 0;
}

int aleqfs_dev_write(struct aleqfs_dev *dev, uint64_t block, const void *buf)
{
    if (dev->fd < 0)
        return -EBADF;
    if (dev->num_blocks && block >= dev->num_blocks)
        return -EIO;
    off_t offset = (off_t)block * (off_t)dev->block_size;
    ssize_t n = pwrite(dev->fd, buf, dev->block_size, offset);
    if (n != (ssize_t)dev->block_size)
        return -EIO;
    dev->dirty = true;
    return 0;
}

int aleqfs_dev_flush(struct aleqfs_dev *dev)
{
    if (dev->fd < 0)
        return -EBADF;
    return fsync(dev->fd) < 0 ? -errno : 0;
}

int aleqfs_dev_sync(struct aleqfs_dev *dev)
{
    if (dev->dirty) {
        int ret = aleqfs_super_sync(dev);
        if (ret) return ret;
    }
    return aleqfs_dev_flush(dev);
}

int aleqfs_dev_create(const char *path, uint64_t size_mb)
{
    struct stat st;
    if (size_mb == 0 || size_mb > (UINT64_MAX / (1024ULL * 1024ULL)))
        return -EINVAL;
    if (stat(path, &st) == 0 && S_ISBLK(st.st_mode))
        return 0;

    uint64_t size = size_mb * 1024ULL * 1024ULL;
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return -errno;
    if (ftruncate(fd, (off_t)size) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    close(fd);
    return 0;
}
