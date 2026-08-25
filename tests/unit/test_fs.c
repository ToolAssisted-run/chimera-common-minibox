/* Virtual filesystem: mounting, open/read/write/seek, fd semantics, errors. */
#include "minibox_internal.h"
#include "test_util.h"
#include <errno.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

static const char DOG[] = "The quick brown fox jumps over the lazy dog.";

static void test_ro_read(void) {
	mb_fs *fs = mb_fs_new();
	CHECK_EQ(mb_fs_mount(fs, "f", (const uint8_t *)DOG, sizeof(DOG)-1, false), 0);
	mb_sword fd = mb_fs_open(fs, "f", O_RDONLY);
	CHECK_EQ(fd, 3);   /* 0,1,2 are stdio */
	uint8_t buf[8];
	CHECK(mb_fs_write(fs, fd, buf, 8) < 0);   /* read-only: write fails */
	CHECK_EQ(mb_fs_read(fs, fd, buf, 8), 8);
	CHECK(memcmp(buf, "The quic", 8) == 0);
	CHECK_EQ(mb_fs_read(fs, fd, buf, 8), 8);
	CHECK(memcmp(buf, "k brown ", 8) == 0);
	mb_fs_free(fs);
}

static void test_seek(void) {
	mb_fs *fs = mb_fs_new();
	mb_fs_mount(fs, "f", (const uint8_t *)DOG, sizeof(DOG)-1, false);
	mb_sword fd = mb_fs_open(fs, "f", O_RDONLY);
	uint8_t buf[4];
	CHECK_EQ(mb_fs_seek(fs, fd, 4, SEEK_SET), 4);
	CHECK_EQ(mb_fs_read(fs, fd, buf, 4), 4);
	CHECK(memcmp(buf, "quic", 4) == 0);
	CHECK_EQ(mb_fs_seek(fs, fd, -4, SEEK_END), (mb_sword)(sizeof(DOG)-1-4));
	CHECK_EQ(mb_fs_read(fs, fd, buf, 4), 4);
	CHECK(memcmp(buf, "dog.", 4) == 0);
	/* out of range seek */
	CHECK(mb_fs_seek(fs, fd, -1, SEEK_SET) < 0);
	mb_fs_free(fs);
}

static void test_rw_write_grow(void) {
	mb_fs *fs = mb_fs_new();
	mb_fs_mount(fs, "z", NULL, 0, true);
	mb_sword fd = mb_fs_open(fs, "z", O_RDWR);
	CHECK_EQ(mb_fs_write(fs, fd, (const uint8_t *)"Big test", 8), 8);
	CHECK_EQ(mb_fs_seek(fs, fd, 0, SEEK_SET), 0);
	CHECK_EQ(mb_fs_write(fs, fd, (const uint8_t *)"Q", 1), 1);
	CHECK_EQ(mb_fs_seek(fs, fd, 2, SEEK_CUR), 3);
	CHECK_EQ(mb_fs_write(fs, fd, (const uint8_t *)")", 1), 1);
	CHECK_EQ(mb_fs_close(fs, fd), 0);
	uint8_t *out; size_t len;
	CHECK_EQ(mb_fs_unmount(fs, "z", &out, &len), 0);
	CHECK_EQ(len, 8);
	CHECK(memcmp(out, "Qig)test", 8) == 0);
	free(out);
	mb_fs_free(fs);
}

static void test_fd_semantics(void) {
	mb_fs *fs = mb_fs_new();
	mb_fs_mount(fs, "a", (const uint8_t *)"x", 1, false);
	mb_fs_mount(fs, "b", (const uint8_t *)"y", 1, false);
	mb_sword fa = mb_fs_open(fs, "a", O_RDONLY);
	mb_sword fb = mb_fs_open(fs, "b", O_RDONLY);
	CHECK_EQ(fa, 3);
	CHECK_EQ(fb, 4);
	/* a read-only mount opens as many times as asked, each open with its
	 * own position (a multi-disc drive holds every disc open) */
	mb_sword fa2 = mb_fs_open(fs, "a", O_RDONLY);
	CHECK_EQ(fa2, 5);
	uint8_t c1 = 0, c2 = 0;
	CHECK_EQ(mb_fs_read(fs, (int)fa, &c1, 1), 1);
	CHECK_EQ(c1, 'x');
	CHECK_EQ(mb_fs_read(fs, (int)fa, &c1, 1), 0);  /* first handle at EOF */
	CHECK_EQ(mb_fs_read(fs, (int)fa2, &c2, 1), 1); /* second still at 0 */
	CHECK_EQ(c2, 'x');
	CHECK_EQ(mb_fs_close(fs, fa2), 0);
	/* close a, its fd frees and is reused */
	CHECK_EQ(mb_fs_close(fs, fa), 0);
	CHECK_EQ(mb_fs_open(fs, "a", O_RDONLY), 3);
	/* a WRITABLE mount stays single-open */
	mb_fs_mount(fs, "w", NULL, 0, true);
	mb_sword fw = mb_fs_open(fs, "w", O_RDWR);
	CHECK(fw >= 0);
	CHECK_EQ(mb_fs_open(fs, "w", O_RDWR), -EACCES);
	CHECK_EQ(mb_fs_open(fs, "w", O_RDONLY), -EACCES);
	mb_fs_close(fs, fw);
	/* open missing -> ENOENT */
	CHECK_EQ(mb_fs_open(fs, "nope", O_RDONLY), -ENOENT);
	mb_fs_free(fs);
}

static void test_mount_errors(void) {
	mb_fs *fs = mb_fs_new();
	/* duplicate name (a stdio device) -> EEXIST */
	CHECK_EQ(mb_fs_mount(fs, "/dev/stdout", NULL, 0, false), -EEXIST);
	/* unmount a permanent device -> error */
	CHECK(mb_fs_unmount(fs, "/dev/stdout", NULL, NULL) != 0);
	/* unmount nonexistent -> ENOENT */
	CHECK_EQ(mb_fs_unmount(fs, "ghost", NULL, NULL), -ENOENT);
	/* unmount while open -> EBUSY */
	mb_fs_mount(fs, "w", NULL, 0, true);
	mb_sword fd = mb_fs_open(fs, "w", O_RDWR);
	CHECK_EQ(mb_fs_unmount(fs, "w", NULL, NULL), -EBUSY);
	mb_fs_close(fs, fd);
	CHECK_EQ(mb_fs_unmount(fs, "w", NULL, NULL), 0);
	mb_fs_free(fs);
}

static void test_stdout_write(void) {
	mb_fs *fs = mb_fs_new();
	/* writing to stdout (fd 1) succeeds and swallows nothing back to the guest */
	CHECK_EQ(mb_fs_write(fs, 1, (const uint8_t *)"", 0), 0);
	/* reading stdin (fd 0) yields 0 (empty) */
	uint8_t b;
	CHECK_EQ(mb_fs_read(fs, 0, &b, 1), 0);
	mb_fs_free(fs);
}

static void run_all(void) {
	RUN(test_ro_read);
	RUN(test_seek);
	RUN(test_rw_write_grow);
	RUN(test_fd_semantics);
	RUN(test_mount_errors);
	RUN(test_stdout_write);
}
TEST_MAIN()
