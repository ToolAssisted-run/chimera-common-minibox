/* waterbox_slots.h: the guest kit's slot-map reader. Guest-kit C that
 * compiles on the host too, which is exactly how it is tested: write a
 * "slots" file into cwd, read it back through the helpers. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <waterbox_slots.h>

int main(void) {
	FILE *f = fopen("slots", "wb");
	assert(f);
	fputs("{\"floppy\":[\"a disk.img\",\"b.img\"],\"cdrom\":[\"game.iso\"],"
	      "\"disc\":[\"x.prx\"],\"rom\":[\"y.nes\"]}", f);
	fclose(f);

	char buf[256];
	assert(wbx_slot_count("floppy") == 2);
	assert(wbx_slot_count("cdrom") == 1);
	assert(wbx_slot_count("nothere") == 0);
	assert(wbx_slot_first("floppy", buf, sizeof buf) && !strcmp(buf, "a disk.img"));
	assert(wbx_slot_name("floppy", 1, buf, sizeof buf) && !strcmp(buf, "b.img"));
	assert(!wbx_slot_name("floppy", 2, buf, sizeof buf));
	assert(!wbx_slot_name("floppy", -1, buf, sizeof buf));
	assert(wbx_slot_first("cdrom", buf, sizeof buf) && !strcmp(buf, "game.iso"));
	assert(wbx_slot_first("disc", buf, sizeof buf) && !strcmp(buf, "x.prx"));
	assert(wbx_slot_first("rom", buf, sizeof buf) && !strcmp(buf, "y.nes"));

	/* no slots file: everything reports absent (the legacy-path signal) */
	remove("slots");
	assert(wbx_slot_count("floppy") == 0);
	assert(!wbx_slot_first("rom", buf, sizeof buf));

	puts("test_slots: all assertions passed");
	return 0;
}
