#define _GNU_SOURCE
/* Virtual filesystem: a flat list of named in-memory files (no directories).
 * Faithful C port of BizHawk waterboxhost src/fs/{mod.rs,regular_file.rs,empty_read.rs,
 * sys_out.rs}. Preloaded /dev/stdin (empty), /dev/stdout, /dev/stderr.
 *
 * Opens are HANDLES with their own positions: a read-only mount may be open
 * any number of times at once (a multi-disc drive legitimately holds every
 * disc open), while a WRITABLE mount stays single-open - concurrent write
 * positions would be a determinism riddle nothing needs solved. File
 * descriptors are the lowest free number, so allocation is deterministic.
 *
 * A read-only mount may also be a file ON THE HOST'S DISK rather than a copy
 * in memory (F_HOST, mb_fs_mount_path). That is not an optimisation: a PS2
 * disc is over four gigabytes and a copy of it is four gigabytes the machine
 * did not need, on top of however many the caller made getting it here. The
 * bytes a guest reads are the same either way, so nothing about the machine
 * changes - and a read-only file has nothing to save, so a savestate does not
 * change either. Writable mounts stay in memory: they are memory cards and
 * save files, they are small, and their contents belong to the machine. */
#include "minibox_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* KStat: exact layout from BizHawk waterboxhost src/syscall_defs.rs (Linux x86-64). */
typedef struct {
	uint64_t st_dev, st_ino, st_nlink;
	uint32_t st_mode, st_uid, st_gid, __pad0;
	uint64_t st_rdev;
	int64_t  st_size, st_blksize, st_blocks;
	int64_t  st_atime_sec, st_atime_nsec, st_mtime_sec, st_mtime_nsec, st_ctime_sec, st_ctime_nsec;
	int64_t  __unused0, __unused1, __unused2;
} kstat;

#define S_IFREG 0100000u
#define S_IFIFO 0010000u
#define S_IRUGO 0000444u
#define S_IWUGO 0000222u
#define O_ACCMODE 0010000003
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

typedef enum { F_EMPTY, F_SYSOUT, F_REGULAR, F_HOST } file_kind;
typedef struct {
	char *name;
	file_kind kind;
	FILE *sysout;      /* F_SYSOUT */
	FILE *host;        /* F_HOST: the file on the host's disk, read on demand */
	uint8_t *data;     /* F_REGULAR */
	size_t len, cap;
	bool writable;     /* F_REGULAR: has no hash */
} mounted_file;

typedef struct {
	int fd;
	size_t file;       /* index into fs->files */
	size_t pos;
} open_handle;

struct mb_fs {
	mounted_file *files; size_t n, cap;
	open_handle *hs; size_t hn, hcap;
	/* staging for F_HOST reads: the kernel writes here, the CPU copies from
	 * here into the guest. See mb_fs_read for why that indirection is required
	 * rather than merely tidy. One buffer for the whole filesystem, because
	 * there is one thread and a read finishes before the next begins. */
	uint8_t bounce[64 * 1024];
};

/* 64-bit seek and tell, spelled for each host.
 *
 * mingw's off_t is FOUR BYTES: fseeko there silently cannot reach past 2GB,
 * which is the exact size this whole mechanism exists to handle, on the exact
 * platform where nothing in the Linux gates would notice. _fseeki64 is the
 * one that works, and MSVC's runtime is what a mingw build links anyway. */
#if defined(_WIN32)
static int seek64(FILE *f, int64_t off, int whence) { return _fseeki64(f, off, whence); }
static int64_t tell64(FILE *f) { return _ftelli64(f); }
#else
static int seek64(FILE *f, int64_t off, int whence) { return fseeko(f, (off_t)off, whence); }
static int64_t tell64(FILE *f) { return (int64_t)ftello(f); }
#endif

static mounted_file *add(mb_fs *fs) {
	if (fs->n == fs->cap) { fs->cap = fs->cap ? fs->cap * 2 : 8; fs->files = realloc(fs->files, fs->cap * sizeof(mounted_file)); }
	mounted_file *f = &fs->files[fs->n++];
	memset(f, 0, sizeof(*f));
	return f;
}

static open_handle *handle_by_fd(mb_fs *fs, int fd) {
	for (size_t i = 0; i < fs->hn; i++) if (fs->hs[i].fd == fd) return &fs->hs[i];
	return NULL;
}

static bool file_is_open(mb_fs *fs, size_t file) {
	for (size_t i = 0; i < fs->hn; i++) if (fs->hs[i].file == file) return true;
	return false;
}

/* lowest free descriptor - deterministic for a deterministic call sequence */
static open_handle *handle_add(mb_fs *fs, size_t file) {
	int fd = 0;
	while (handle_by_fd(fs, fd)) fd++;
	if (fs->hn == fs->hcap) { fs->hcap = fs->hcap ? fs->hcap * 2 : 8; fs->hs = realloc(fs->hs, fs->hcap * sizeof(open_handle)); }
	open_handle *h = &fs->hs[fs->hn++];
	h->fd = fd; h->file = file; h->pos = 0;
	return h;
}

mb_fs *mb_fs_new(void) {
	mb_fs *fs = calloc(1, sizeof(mb_fs));
	mounted_file *f;
	f = add(fs); f->name = strdup("/dev/stdin");  f->kind = F_EMPTY;
	f = add(fs); f->name = strdup("/dev/stdout"); f->kind = F_SYSOUT; f->sysout = stdout;
	f = add(fs); f->name = strdup("/dev/stderr"); f->kind = F_SYSOUT; f->sysout = stderr;
	handle_add(fs, 0); /* fd 0 */
	handle_add(fs, 1); /* fd 1 */
	handle_add(fs, 2); /* fd 2 */
	return fs;
}

void mb_fs_free(mb_fs *fs) {
	if (!fs) return;
	for (size_t i = 0; i < fs->n; i++) {
		free(fs->files[i].name);
		free(fs->files[i].data);
		if (fs->files[i].kind == F_HOST && fs->files[i].host) fclose(fs->files[i].host);
	}
	free(fs->files); free(fs->hs); free(fs);
}

static mounted_file *by_name(mb_fs *fs, const char *name) {
	for (size_t i = 0; i < fs->n; i++) if (strcmp(fs->files[i].name, name) == 0) return &fs->files[i];
	return NULL;
}

int mb_fs_mount(mb_fs *fs, const char *name, const uint8_t *data, size_t len, bool writable) {
	if (by_name(fs, name)) return -EEXIST;
	mounted_file *f = add(fs);
	f->name = strdup(name); f->kind = F_REGULAR; f->writable = writable;
	f->len = f->cap = len; f->data = malloc(len ? len : 1);
	if (len) memcpy(f->data, data, len);
	return 0;
}

/* Mounts a host file read-only, without reading it. The length is taken once,
 * here, and is what the guest is told and held to: a file that changes under a
 * running machine is the caller's mistake, and letting the size drift would
 * turn it into a nondeterminism nobody could see. */
int mb_fs_mount_path(mb_fs *fs, const char *name, const char *path) {
	if (by_name(fs, name)) return -EEXIST;
	FILE *fp = fopen(path, "rb");
	if (!fp) return -ENOENT;
	if (seek64(fp, 0, SEEK_END) != 0) { fclose(fp); return -EIO; }
	int64_t end = tell64(fp);
	if (end < 0) { fclose(fp); return -EIO; }
	mounted_file *f = add(fs);
	f->name = strdup(name); f->kind = F_HOST; f->writable = false;
	f->host = fp; f->len = f->cap = (size_t)end; f->data = NULL;
	return 0;
}

int mb_fs_unmount(mb_fs *fs, const char *name, uint8_t **out_data, size_t *out_len) {
	for (size_t i = 0; i < fs->n; i++) {
		if (strcmp(fs->files[i].name, name) == 0) {
			mounted_file *f = &fs->files[i];
			if (f->kind != F_REGULAR && f->kind != F_HOST) return -EINVAL;   /* permanent (stdio) */
			if (file_is_open(fs, i)) return -EBUSY;      /* still open */
			if (f->kind == F_HOST) {
				/* nothing to hand back: the bytes never left the disk */
				if (out_data) { *out_data = NULL; *out_len = 0; }
				fclose(f->host);
			}
			else if (out_data) { *out_data = f->data; *out_len = f->len; } else free(f->data);
			free(f->name);
			memmove(&fs->files[i], &fs->files[i+1], (fs->n - i - 1) * sizeof(mounted_file));
			fs->n--;
			/* handles index into the files array; later entries just moved */
			for (size_t j = 0; j < fs->hn; j++) if (fs->hs[j].file > i) fs->hs[j].file--;
			return 0;
		}
	}
	return -ENOENT;
}

mb_sword mb_fs_open(mb_fs *fs, const char *name, int flags) {
	mounted_file *f = by_name(fs, name);
	if (!f) return -ENOENT;
	size_t idx = (size_t)(f - fs->files);
	/* writable files stay single-open; read-only mounts may be opened many
	 * times, each open with its own position */
	if (f->kind == F_REGULAR && f->writable && file_is_open(fs, idx)) return -EACCES;
	bool can_read = f->kind != F_SYSOUT;
	bool can_write = (f->kind == F_SYSOUT) || (f->kind == F_REGULAR && f->writable);
	switch (flags & O_ACCMODE) {
		case O_RDONLY: if (!can_read) return -EACCES; break;
		case O_WRONLY: if (!can_write) return -EACCES; break;
		case O_RDWR:   if (!can_read || !can_write) return -EACCES; break;
		default: return -EINVAL;
	}
	return handle_add(fs, idx)->fd;
}

mb_sword mb_fs_close(mb_fs *fs, int fd) {
	open_handle *h = handle_by_fd(fs, fd);
	if (!h) return -EBADF;
	*h = fs->hs[--fs->hn]; /* order does not matter; fds identify handles */
	return 0;
}

mb_sword mb_fs_read(mb_fs *fs, int fd, uint8_t *buf, size_t n) {
	open_handle *h = handle_by_fd(fs, fd);
	if (!h) return -ENOENT;
	mounted_file *f = &fs->files[h->file];
	if (f->kind == F_EMPTY) return 0;
	if (f->kind == F_SYSOUT) return -EBADF;
	size_t avail = f->len - h->pos, take = n < avail ? n : avail;
	if (f->kind == F_HOST) {
		/* The handle's position is the guest's; the host file's own position is
		 * shared between every handle on it, so it is set from ours each time
		 * rather than trusted.
		 *
		 * THE BOUNCE BUFFER IS NOT AN OPTIMISATION. `buf` is GUEST memory, and
		 * guest pages are mapped read-only until something writes to them - the
		 * write fault is how this host knows a page became dirty and belongs in
		 * a savestate. A CPU store faults and is caught; a KERNEL write to the
		 * same address does not, it just returns EFAULT. So a read big enough
		 * for stdio to hand the guest's pointer straight to read(2) comes back
		 * short, the guest gets fewer bytes than it asked for, and the machine
		 * quietly diverges. (It did: PCSX2's EE RAM differed from its native
		 * reference in 5778 bytes.) Reading into host memory and copying with
		 * the CPU keeps every guest write a guest write. */
		if (take == 0) return 0;
		if (seek64(f->host, (int64_t)h->pos, SEEK_SET) != 0) return -EIO;
		size_t done = 0;
		while (done < take) {
			size_t want = take - done;
			if (want > sizeof fs->bounce) want = sizeof fs->bounce;
			size_t got = fread(fs->bounce, 1, want, f->host);
			if (got == 0) {
				if (ferror(f->host)) { clearerr(f->host); return done ? (mb_sword)done : -EIO; }
				break;   /* end of file, which the length said could not happen */
			}
			memcpy(buf + done, fs->bounce, got);
			done += got;
		}
		h->pos += done;
		return (mb_sword)done;
	}
	memcpy(buf, f->data + h->pos, take); h->pos += take;
	return (mb_sword)take;
}

mb_sword mb_fs_write(mb_fs *fs, int fd, const uint8_t *buf, size_t n) {
	open_handle *h = handle_by_fd(fs, fd);
	if (!h) return -ENOENT;
	mounted_file *f = &fs->files[h->file];
	if (f->kind == F_SYSOUT) { fwrite(buf, 1, n, f->sysout); return (mb_sword)n; } /* host errors swallowed */
	if (f->kind == F_EMPTY || !f->writable) return -EBADF;
	size_t newpos = h->pos + n;
	if (newpos > f->cap) { f->cap = newpos; f->data = realloc(f->data, f->cap); }
	memcpy(f->data + h->pos, buf, n);
	h->pos = newpos;
	if (newpos > f->len) f->len = newpos;
	return (mb_sword)n;
}

mb_sword mb_fs_seek(mb_fs *fs, int fd, mb_sword offset, int whence) {
	open_handle *h = handle_by_fd(fs, fd);
	if (!h) return -EINVAL;
	mounted_file *f = &fs->files[h->file];
	if (f->kind != F_REGULAR && f->kind != F_HOST) return -EINVAL;
	mb_sword newpos;
	switch (whence) {
		case SEEK_SET: newpos = offset; break;
		case SEEK_CUR: newpos = (mb_sword)h->pos + offset; break;
		case SEEK_END: newpos = (mb_sword)f->len + offset; break;
		default: return -EINVAL;
	}
	if (newpos < 0 || newpos > (mb_sword)f->len) return -EINVAL;
	h->pos = (size_t)newpos;
	return newpos;
}

static void fill_stat(kstat *s, bool can_read, bool can_write, bool can_seek, int64_t length) {
	memset(s, 0, sizeof(*s));
	s->st_dev = 1; s->st_ino = 1; s->st_nlink = 0;
	uint32_t mode = 0;
	if (can_read) mode |= S_IRUGO;
	if (can_write) mode |= S_IWUGO;
	mode |= can_seek ? S_IFREG : S_IFIFO;
	s->st_mode = mode;
	s->st_size = can_seek ? length : 0;
	s->st_blksize = 4096;
	s->st_blocks = (s->st_size + 511) / 512;
	s->st_atime_sec = s->st_mtime_sec = s->st_ctime_sec = 1262304000000LL;
	s->st_atime_nsec = s->st_mtime_nsec = s->st_ctime_nsec = 500000000LL;
}

static mb_sword stat_file(mounted_file *f, kstat *s) {
	if (f->kind == F_SYSOUT) fill_stat(s, false, true, false, 0);
	else if (f->kind == F_EMPTY) fill_stat(s, true, false, false, 0);
	else fill_stat(s, true, f->writable, true, (int64_t)f->len);   /* F_HOST: writable is false */
	return 0;
}

mb_sword mb_fs_stat_name(mb_fs *fs, const char *name, void *ks) {
	mounted_file *f = by_name(fs, name); if (!f) return -ENOENT; return stat_file(f, (kstat *)ks);
}
mb_sword mb_fs_stat_fd(mb_fs *fs, int fd, void *ks) {
	open_handle *h = handle_by_fd(fs, fd); if (!h) return -ENOENT; return stat_file(&fs->files[h->file], (kstat *)ks);
}
mb_sword mb_fs_truncate_name(mb_fs *fs, const char *name, mb_sword size) {
	mounted_file *f = by_name(fs, name);
	if (!f) return -ENOENT;
	if (f->kind != F_REGULAR || !f->writable || size < 0) return -EBADF;
	f->data = realloc(f->data, size ? size : 1); f->len = f->cap = (size_t)size;
	for (size_t j = 0; j < fs->hn; j++) {
		if (&fs->files[fs->hs[j].file] == f && fs->hs[j].pos > f->len) fs->hs[j].pos = f->len;
	}
	return 0;
}
mb_sword mb_fs_truncate_fd(mb_fs *fs, int fd, mb_sword size) {
	open_handle *h = handle_by_fd(fs, fd); if (!h) return -ENOENT; return mb_fs_truncate_name(fs, fs->files[h->file].name, size);
}
