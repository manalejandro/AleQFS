# AleQFS — Adaptive Linux Efficient QUANTUM Filesystem

AleQFS is a **quantum-inspired** Linux filesystem that simulates superposition,
entanglement, and Grover search — all running on classical hardware with a native
kernel module (no FUSE).

## Quantum Features

- **Superposition** — Files can exist in multiple directories simultaneously
  via probability amplitude fields. Reading a file "collapses" its quantum state.
- **Entanglement** — Directories can be entangled so operations on one
  instantly mirror to the other (spooky action at a distance).
- **Grover Search** — O(1) hash-based quantum search index replacing
  traditional B-trees. Pattern matching across all entries in constant time.
- **Decoherence Detection** — Each block carries a quantum checksum.
  Tampering triggers decoherence, making corrupted data detectable.
- **Quantum Temperature** — The system runs near absolute zero (0.01 K)
  to maintain coherence.

## Quick Start

```bash
# Build
make

# Format a 64 MiB quantum image
./mkfs.aleqfs /tmp/test.qfs 64
# or: ./aleqfs format /tmp/test.qfs 64

# Check quantum status
./aleqfs qstatus /tmp/test.qfs

# Create directories and files (superposition-enabled)
./aleqfs mkdir /tmp/test.qfs /hello
./aleqfs create /tmp/test.qfs /hello/world.txt

# Entangle two directories
./aleqfs mkdir /tmp/test.qfs /a
./aleqfs mkdir /tmp/test.qfs /b
./aleqfs entangle /tmp/test.qfs /a /b

# Observe quantum state (collapses superposition)
./aleqfs observe /tmp/test.qfs /hello/world.txt

# Grover search
./aleqfs grover /tmp/test.qfs 1

# Mount (requires kernel module; Linux >= 6.3, tested up to 7.2)
sudo modprobe aleqfs_ko        # also auto-loaded by "mount -t aleqfs"
sudo mount -t aleqfs /tmp/test.qfs /mnt
```

## Commands

| Command | Description |
|---------|-------------|
| `format <img> <size_mb>` | Create and format a new quantum image (1..512 MiB) |
| `mkfs <device> [size_mb]` | Format a device or image |
| `ls <img> <path>` | List directory contents (quantum collapse with --collapse) |
| `mkdir <img> <path>` | Create a directory (fails if it already exists) |
| `rmdir <img> <path>` | Remove an empty directory |
| `cp-in <img> <src> <dst>` | Copy a file into the image (replaces an existing dst) |
| `cat <img> <path>` | Display file contents |
| `stat <img> <path>` | Show file metadata + quantum state + coherence check |
| `mv <img> <src> <dst>` | Rename/move (replaces an existing dst file) |
| `rm <img> <path>` | Remove a file (releases its blocks and grover key) |
| `create <img> <path>` | Create an empty file (fails if it already exists) |
| `tree <img> <path>` | Show directory tree (quantum collapse with --collapse) |
| `dump <img>` | Display superblock info (quantum parameters + seal status) |
| `entangle <img> <path_a> <path_b>` | Entangle two directories |
| `observe <img> <path>` | Collapse quantum state and read |
| `decohere <img> <path>` | Force decoherence on a file (seal check will fail) |
| `grover <img> <pattern>` | Grover quantum search (bitmask over indexed keys) |
| `qstatus <img>` | Quantum system status |

Notes:

- The **Grover index** is populated by the CLI (`mkdir`, `create`, `cp-in`, `mv`)
  using a 64-bit hash of the path as key and the inode number as value.
  `grover <img> <pattern>` matches every key where `(key & pattern) == pattern`;
  `pattern 0` lists the whole index. Files created through the mounted kernel
  filesystem are not indexed.
- **Decoherence detection**: `cp-in`/kernel writes seal the first data block of a
  file with an FNV-1a checksum (`stat` reports `Coherence:`). The superblock
  carries its own seal, verified on every load and mount.
- Filesystem limits: 4 KiB blocks, max image size 512 MiB (allocation bitmap),
  1024 inodes, up to 4 extents per file (each extent grows without limit while
  physically contiguous blocks are available). Holes created by seeks are
  zero-filled on write.

## Source Layout

```
src/
├── aleqfs.h        — Core quantum structures and API
├── aleqfs_layout.h — Shared on-disk quantum layout (kernel + userspace)
├── main.c          — CLI entry point and quantum commands
├── super.c         — Quantum superblock operations
├── io.c            — Block device read/write
├── bitmap.c        — Free block/inode bitmap
├── inode.c         — Quantum inode allocation
├── extent.c        — Extent-based file I/O
├── dir.c           — Quantum directory operations (superposition)
├── path.c          — Path resolution
├── grover.c        — Grover quantum search index
├── entangle.c      — Quantum entanglement operations
├── checksum.c      — Decoherence detection via checksums
├── quantum.c       — Quantum state management
└── aleqfs_ko.c     — Linux kernel module (VFS driver)
```

## Build Options

```bash
make              # Release build
make CFLAGS="-g"  # Debug build
make check        # Run quantum test suite (basic + regression + corrupt-image)
make kmod         # Build kernel module
make deb          # Build .deb package
make install      # Install to /usr/local
```

## Kernel Module

Requires Linux >= 6.3 (compiled and tested up to 7.2; DKMS rebuilds it for
each kernel).

```bash
sudo apt install dkms linux-headers-amd64
sudo make deb
sudo apt install ./pkg/aleqfs-2.0.0.deb
sudo modprobe aleqfs_ko          # or just mount: the fs alias autoloads it
sudo mount -t aleqfs /tmp/test.qfs /mnt
```

`mount.aleqfs <device>` without a mountpoint (e.g. from the bundled udev rule)
automounts on `/media/aleqfs/<device-name>`.

The kernel driver validates the superblock, geometry, checksums and every
on-disk extent before use: corrupt or hostile images are rejected at mount
time instead of corrupting memory. Unlinked files release their blocks and
inode through `->evict_inode`; truncate/`O_TRUNC` is supported.

## Testing

```bash
make check                 # built-in functional suite
./tests/test_basic.sh      # CLI walkthrough
./tests/test_regress.sh    # regressions: compaction, EEXIST, overwrite,
                           # journal growth, grover, decoherence, corrupt images
./tests/test_stress.sh     # 100-file creation
```

## Supporting file types

AleQFS supports **regular files** and **directories** plus **entangled directories**
(linked pairs). Symlinks, device nodes, FIFOs, and sockets are not supported.
