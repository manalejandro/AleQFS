CC      ?= gcc
CFLAGS  ?= -O2
PREFIX  ?= /usr/local

CFLAGS  += -Wall -Wextra -Wpedantic -Werror=implicit-function-declaration \
           -Werror=return-type -Wstrict-prototypes -Wvla \
           -std=gnu11 -D_GNU_SOURCE \
           -DALEFS_VERSION=\"$(VERSION)\"
LDFLAGS += -lm -lpthread

HAS_ZSTD  := $(shell pkg-config --exists libzstd 2>/dev/null && echo 1 || echo 0)
HAS_LZ4   := $(shell pkg-config --exists liblz4  2>/dev/null && echo 1 || echo 0)
HAS_BLAKE3 := $(shell pkg-config --exists libblake3 2>/dev/null && echo 1 || echo 0)

ifeq ($(HAS_ZSTD),1)
CFLAGS  += $(shell pkg-config --cflags libzstd) -DHAS_ZSTD
LDFLAGS += $(shell pkg-config --libs libzstd)
endif

ifeq ($(HAS_LZ4),1)
CFLAGS  += $(shell pkg-config --cflags liblz4) -DHAS_LZ4
LDFLAGS += $(shell pkg-config --libs liblz4)
endif

ifeq ($(HAS_BLAKE3),1)
CFLAGS  += $(shell pkg-config --cflags libblake3) -DHAS_BLAKE3
LDFLAGS += $(shell pkg-config --libs libblake3)
endif

SRCDIR   = src
BUILDDIR = build
VERSION  := $(patsubst v%,%,$(shell git describe --tags 2>/dev/null || echo "2.0.0"))

KMOD_SRC := $(SRCDIR)/aleqfs_ko.c

SRCS := $(filter-out $(KMOD_SRC) $(SRCDIR)/alefs_ko.c $(SRCDIR)/alefs.h $(SRCDIR)/alefs_layout.h,$(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*.h))
SRCS := $(filter-out $(SRCDIR)/btree.c,$(SRCS))
SRCS := $(filter-out $(SRCDIR)/compression.c $(SRCDIR)/encryption.c $(SRCDIR)/dedup.c,$(SRCS))
SRCS := $(filter-out $(SRCDIR)/erasure.c $(SRCDIR)/tiering.c $(SRCDIR)/gc.c,$(SRCS))
SRCS := $(filter-out $(SRCDIR)/prefetch.c $(SRCDIR)/versioning.c,$(SRCS))
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(filter %.c,$(SRCS)))
DEPS := $(OBJS:.o=.d)

TARGET = aleqfs

KMOD_DIR  = $(BUILDDIR)/kmod
KMOD_OBJ  = $(KMOD_DIR)/aleqfs.ko

.PHONY: all clean install uninstall check test testv kmod

all: $(BUILDDIR) $(TARGET)
	@ln -sf $(TARGET) mkfs.aleqfs 2>/dev/null || true
	@ln -sf $(TARGET) mount.aleqfs 2>/dev/null || true

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)
	@echo "  LD  $@"
	@echo "  Quantum Features: ZSTD=$(HAS_ZSTD) LZ4=$(HAS_LZ4) BLAKE3=$(HAS_BLAKE3)"

KVER    ?= $(shell uname -r)
KDIR    ?= /lib/modules/$(KVER)/build

kmod: $(KMOD_OBJ)

$(KMOD_DIR):
	mkdir -p $(KMOD_DIR)

$(KMOD_OBJ): $(KMOD_DIR) $(KMOD_SRC) $(SRCDIR)/aleqfs_layout.h
	cp $(KMOD_SRC) $(KMOD_DIR)/aleqfs_ko.c
	cp $(SRCDIR)/aleqfs_layout.h $(KMOD_DIR)/
	echo "obj-m := aleqfs_ko.o" > $(KMOD_DIR)/Makefile
	$(MAKE) -C $(KDIR) M=$(PWD)/$(KMOD_DIR) modules

TEST_IMG = /tmp/aleqfs-test-$$(id -u).bin

check: $(TARGET)
	@echo "=== AleQFS Quantum Test Suite ==="
	@-rm -f $(TEST_IMG)
	@echo "1. Format..."
	./$(TARGET) format $(TEST_IMG) 64
	@echo "2. Quantum status..."
	./$(TARGET) qstatus $(TEST_IMG)
	@echo "3. Directory operations..."
	./$(TARGET) mkdir $(TEST_IMG) /subdir
	./$(TARGET) ls $(TEST_IMG) /
	@echo "4. File operations..."
	@echo "hello quantum world" > /tmp/aleqfs_content.txt
	./$(TARGET) cp-in $(TEST_IMG) /tmp/aleqfs_content.txt /subdir/hello.txt
	./$(TARGET) cat $(TEST_IMG) /subdir/hello.txt
	./$(TARGET) stat $(TEST_IMG) /subdir/hello.txt
	./$(TARGET) ls $(TEST_IMG) /subdir
	@echo "5. Rename..."
	./$(TARGET) mv $(TEST_IMG) /subdir/hello.txt /subdir/world.txt
	./$(TARGET) ls $(TEST_IMG) /subdir
	@echo "6. Delete..."
	./$(TARGET) rm $(TEST_IMG) /subdir/world.txt
	./$(TARGET) ls $(TEST_IMG) /subdir
	@echo "7. Subdir..."
	./$(TARGET) rmdir $(TEST_IMG) /subdir
	./$(TARGET) ls $(TEST_IMG) /
	@echo "8. Quantum entanglement..."
	./$(TARGET) mkdir $(TEST_IMG) /a
	./$(TARGET) mkdir $(TEST_IMG) /b
	./$(TARGET) entangle $(TEST_IMG) /a /b
	./$(TARGET) qstatus $(TEST_IMG)
	@echo "9. Quantum observation..."
	./$(TARGET) create $(TEST_IMG) /a/qfile.txt
	./$(TARGET) observe $(TEST_IMG) /a/qfile.txt
	./$(TARGET) stat $(TEST_IMG) /a/qfile.txt
	@echo "10. Grover search..."
	./$(TARGET) grover $(TEST_IMG) 1
	@echo "11. Deep tree..."
	./$(TARGET) mkdir $(TEST_IMG) /x
	./$(TARGET) mkdir $(TEST_IMG) /x/y
	./$(TARGET) mkdir $(TEST_IMG) /x/y/z
	./$(TARGET) create $(TEST_IMG) /x/y/z/file.txt
	./$(TARGET) tree $(TEST_IMG) /
	@echo "12. Superblock dump..."
	./$(TARGET) dump $(TEST_IMG)
	@echo "13. Regression suite..."
	./tests/test_regress.sh
	@-rm -f $(TEST_IMG) /tmp/aleqfs_content.txt
	@echo "=== All AleQFS tests passed ==="

test: check

testv: $(TARGET)
	valgrind --tool=memcheck --leak-check=full ./$(TARGET) format /tmp/aleqfs-vtest.bin 32 2>&1 | head -20
	@rm -f /tmp/aleqfs-vtest.bin

install: $(TARGET)
	install -d $(DESTDIR)/sbin $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	ln -sf $(TARGET) $(DESTDIR)$(PREFIX)/bin/mkfs.aleqfs 2>/dev/null || true
	ln -sf $(PREFIX)/bin/$(TARGET) $(DESTDIR)/sbin/mount.aleqfs 2>/dev/null || true
	@echo "AleQFS installed to $(DESTDIR)$(PREFIX)/bin/$(TARGET)"
	@echo "  mkfs.aleqfs -> aleqfs (symlink)"
	@echo "  mount.aleqfs -> aleqfs (symlink)"
	@if [ -f $(KMOD_OBJ) ]; then \
		install -d $(DESTDIR)$(PREFIX)/lib/modules/$(KVER)/extra; \
		install -m 644 $(KMOD_OBJ) $(DESTDIR)$(PREFIX)/lib/modules/$(KVER)/extra/; \
		echo "  aleqfs.ko installed to kernel modules"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/bin/mkfs.aleqfs
	rm -f $(DESTDIR)/sbin/mount.aleqfs

format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SRCDIR)/*.c $(SRCDIR)/*.h; \
	else \
		echo "clang-format not installed, skipping"; \
	fi

clean:
	rm -rf $(BUILDDIR) $(TARGET)
	rm -f mkfs.aleqfs mount.aleqfs
	rm -f /tmp/aleqfs-test-*.bin
	$(MAKE) -C $(KDIR) M=$(PWD)/build/kmod clean 2>/dev/null || true

deb: $(TARGET)
	@echo "=== Building AleQFS .deb package ==="
	rm -rf pkg/deb
	mkdir -p pkg/deb/DEBIAN \
	         pkg/deb/usr/bin \
	         pkg/deb/usr/sbin \
	         pkg/deb/usr/src \
	         pkg/deb/usr/share/doc/aleqfs/dkms \
	         pkg/deb/usr/share/man/man1 \
	         pkg/deb/usr/share/man/man8 \
	         pkg/deb/lib/udev/rules.d
	cp $(TARGET) pkg/deb/usr/bin/aleqfs
	ln -sf aleqfs pkg/deb/usr/bin/mkfs.aleqfs
	ln -sf /usr/bin/aleqfs pkg/deb/usr/sbin/mount.aleqfs
	cp README.md LICENSE pkg/deb/usr/share/doc/aleqfs/
	echo "AleQFS $(VERSION) changelog" | gzip -9nf > pkg/deb/usr/share/doc/aleqfs/changelog.gz
	chmod 644 pkg/deb/usr/share/doc/aleqfs/*.md
	chmod 644 pkg/deb/usr/share/doc/aleqfs/LICENSE 2>/dev/null || true
	cp scripts/90-aleqfs.rules pkg/deb/lib/udev/rules.d/
	cp src/aleqfs_ko.c pkg/deb/usr/share/doc/aleqfs/dkms/
	cp src/aleqfs_layout.h pkg/deb/usr/share/doc/aleqfs/dkms/
	cp dkms/dkms.conf pkg/deb/usr/share/doc/aleqfs/dkms/
	cp dkms/Makefile pkg/deb/usr/share/doc/aleqfs/dkms/
	printf '.TH ALEQFS 1 "July 2026" "aleqfs %s" "User Commands"\n.SH NAME\nalefs \\- Adaptive Linux Efficient QUANTUM Filesystem\n.SH SYNOPSIS\n.B aleqfs\n.I command\n.RI [ options ]\n.SH DESCRIPTION\nAleQFS quantum filesystem image tool.\n.SH COMMANDS\n.TP\n.B format \\fIimg\\fR \\fIsize_mb\\fR\nFormat quantum image.\n.TP\n.B ls \\fIimg\\fR \\fIpath\\fR\nList directory (with quantum collapse).\n.TP\n.B mkdir \\fIimg\\fR \\fIpath\\fR\nCreate directory.\n.TP\n.B rmdir \\fIimg\\fR \\fIpath\\fR\nRemove directory.\n.TP\n.B cp-in \\fIimg\\fR \\fIsrc\\fR \\fIdst\\fR\nCopy file into image.\n.TP\n.B cat \\fIimg\\fR \\fIpath\\fR\nShow file contents.\n.TP\n.B stat \\fIimg\\fR \\fIpath\\fR\nShow file metadata + quantum state.\n.TP\n.B mv \\fIimg\\fR \\fIsrc\\fR \\fIdst\\fR\nRename.\n.TP\n.B rm \\fIimg\\fR \\fIpath\\fR\nRemove file.\n.TP\n.B create \\fIimg\\fR \\fIpath\\fR\nCreate empty file.\n.TP\n.B tree \\fIimg\\fR \\fIpath\\fR\nDirectory tree.\n.TP\n.B dump \\fIimg\\fR\nSuperblock dump.\n.TP\n.B entangle \\fIimg\\fR \\fIpath_a\\fR \\fIpath_b\\fR\nEntangle two directories.\n.TP\n.B observe \\fIimg\\fR \\fIpath\\fR\nCollapse quantum state and read.\n.TP\n.B decohere \\fIimg\\fR \\fIpath\\fR\nForce decoherence on file.\n.TP\n.B grover \\fIimg\\fR \\fIpattern\\fR\nQuantum grover search.\n.TP\n.B qstatus \\fIimg\\fR\nQuantum system status.\n.SH LICENSE\nMIT\n' | gzip -9nf > pkg/deb/usr/share/man/man1/aleqfs.1.gz
	printf '.TH MKFS.ALEQFS 8 "July 2026" "mkfs.aleqfs %s" "System Administration"\n.SH NAME\nmkfs.aleqfs \\- build an AleQFS quantum filesystem\n.SH SYNOPSIS\n.B mkfs.aleqfs\n.RI [ options ]\n.I device\n.RI [ size_mb ]\n.SH DESCRIPTION\nmkfs.aleqfs creates an AleQFS quantum filesystem.\n.SH OPTIONS\n.B -V\nPrint version.\n.TP\n.B -h, --help\nThis help.\n.SH LICENSE\nMIT\n' | gzip -9nf > pkg/deb/usr/share/man/man8/mkfs.aleqfs.8.gz
	printf '.TH MOUNT.ALEQFS 8 "July 2026" "mount.aleqfs %s" "System Administration"\n.SH NAME\nmount.aleqfs \\- mount an AleQFS quantum filesystem\n.SH SYNOPSIS\n.B mount -t aleqfs\n.I device\n.I mountpoint\n.SH DESCRIPTION\nmount.aleqfs is called by mount(8) to mount AleQFS.\nRequires the aleqfs kernel module built via DKMS.\n.SH LICENSE\nMIT\n' | gzip -9nf > pkg/deb/usr/share/man/man8/mount.aleqfs.8.gz
	printf 'Package: aleqfs\nVersion: %s\nSection: utils\nPriority: optional\nArchitecture: amd64\nMaintainer: AleQFS Contributors <aleqfs@example.com>\nDepends: libc6 (>= 2.17)\nRecommends: dkms, linux-headers-generic\nDescription: Adaptive Linux Efficient Quantum Filesystem\n AleQFS is a quantum Linux filesystem with native kernel module (DKMS).\n Features superposition, entanglement, and Grover search.\n Includes mkfs.aleqfs and mount.aleqfs helpers.\n .\n The kernel module is built for the current kernel via DKMS\n on package install. Run "modprobe aleqfs" after installation.\nHomepage: https://github.com/anomalyco/opencode\n' "$(VERSION)" > pkg/deb/DEBIAN/control
	printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: aleqfs\n\nFiles: *\nCopyright: 2026 AleQFS Contributors\nLicense: MIT\n' > pkg/deb/DEBIAN/copyright
	cat LICENSE >> pkg/deb/DEBIAN/copyright
	sed 's/@VERSION@/$(VERSION)/g' scripts/postinst > pkg/deb/DEBIAN/postinst
	chmod 755 pkg/deb/DEBIAN/postinst
	sed 's/@VERSION@/$(VERSION)/g' scripts/postrm > pkg/deb/DEBIAN/postrm
	chmod 755 pkg/deb/DEBIAN/postrm
	sed 's/@VERSION@/$(VERSION)/g' scripts/preinst > pkg/deb/DEBIAN/preinst
	chmod 755 pkg/deb/DEBIAN/preinst
	fakeroot dpkg-deb --build pkg/deb pkg/aleqfs-$(VERSION).deb
	@echo "Package: pkg/aleqfs-$(VERSION).deb"

dist: clean
	tar czf aleqfs-$(VERSION).tar.gz src/ Makefile README.md tests/ LICENSE pkg/

-include $(DEPS)
