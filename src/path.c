#include "aleqfs.h"
#include <string.h>
#include <errno.h>

#define ALEQFS_MAX_PATH_DEPTH 256

/*
 * Walk every component of path, resolving "." and ".." through an
 * ancestor stack, and return the final inode.
 */
static int path_walk(struct aleqfs_dev *dev, const char *path, uint64_t *ino)
{
    char work[ALEQFS_MAX_NAME * 16];
    size_t plen = strlen(path);
    uint64_t stack[ALEQFS_MAX_PATH_DEPTH];
    int sp = 0;
    char *saveptr;
    char *token;

    if (plen >= sizeof(work))
        return -ENAMETOOLONG;
    memcpy(work, path, plen + 1);

    stack[sp++] = dev->sb.root_inode;

    token = strtok_r(work, "/", &saveptr);
    while (token) {
        uint64_t next_ino;
        int ret;

        if (strlen(token) > ALEQFS_MAX_NAME)
            return -ENAMETOOLONG;

        if (strcmp(token, ".") == 0) {
            token = strtok_r(NULL, "/", &saveptr);
            continue;
        }
        if (strcmp(token, "..") == 0) {
            if (sp > 1)
                sp--;
            token = strtok_r(NULL, "/", &saveptr);
            continue;
        }

        ret = aleqfs_dir_lookup(dev, stack[sp - 1], token, &next_ino);
        if (ret)
            return ret;

        if (sp >= ALEQFS_MAX_PATH_DEPTH)
            return -ENAMETOOLONG;
        stack[sp++] = next_ino;

        token = strtok_r(NULL, "/", &saveptr);
    }

    *ino = stack[sp - 1];
    return 0;
}

int aleqfs_path_resolve(struct aleqfs_dev *dev, const char *path,
                        uint64_t *parent_ino, char *leaf)
{
    char work[ALEQFS_MAX_NAME * 16];
    size_t plen = strlen(path);
    char leafbuf[ALEQFS_MAX_NAME + 1];
    char *saveptr;
    char *token;
    char *prev = NULL;
    int ret;

    if (plen >= sizeof(work))
        return -ENAMETOOLONG;
    memcpy(work, path, plen + 1);

    /* tokenize to find the last component (the leaf) */
    token = strtok_r(work, "/", &saveptr);
    while (token) {
        prev = token;
        token = strtok_r(NULL, "/", &saveptr);
    }

    if (!prev) {
        /* path is "/" (or empty): the root itself */
        *parent_ino = dev->sb.root_inode;
        leaf[0] = '\0';
        return 0;
    }

    if (strlen(prev) > ALEQFS_MAX_NAME)
        return -ENAMETOOLONG;
    if (strcmp(prev, ".") == 0 || strcmp(prev, "..") == 0)
        return -EINVAL; /* "."/".." are not names that can be created */

    memcpy(leafbuf, prev, strlen(prev) + 1);

    if (prev == work) {
        /* single component: the parent is the root */
        *parent_ino = dev->sb.root_inode;
    } else {
        /*
         * strtok replaced every separator with NUL: restore the ones
         * before the leaf so work holds the parent path ("a/b/"), then
         * walk it ("." / ".." aware).
         */
        uint64_t parent;
        char *p;

        for (p = work; p < prev - 1; p++)
            if (*p == '\0')
                *p = '/';
        prev[-1] = '/';
        prev[0] = '\0';

        ret = path_walk(dev, work, &parent);
        if (ret)
            return ret;
        *parent_ino = parent;
    }

    memcpy(leaf, leafbuf, strlen(leafbuf) + 1);
    return 0;
}

int aleqfs_path_resolve_full(struct aleqfs_dev *dev, const char *path,
                             uint64_t *ino)
{
    return path_walk(dev, path, ino);
}
