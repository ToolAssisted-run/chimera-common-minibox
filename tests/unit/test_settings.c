/* waterbox_settings.h, compiled on the host as test_slots.c is: the reader
 * walks keys only, so a string VALUE equal to the key asked for is not taken
 * for it. The shipped flycast and pcsx2 packages have such a pair -
 * textureFiltering may be "machine", and a setting named machine exists - and
 * were safe only because machine is declared first. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "waterbox_settings.h"

int main(void)
{
	const char *json = "{\"textureFiltering\":\"machine\",\"machine\":\"naomi\",\"scale\":3,\"fast\":true}";
	wbx_settings_use_buffer(json, (int)strlen(json));
	char out[64];
	assert(wbx_setting_str("machine", out, sizeof out) == 5 && strcmp(out, "naomi") == 0);
	assert(wbx_setting_str("textureFiltering", out, sizeof out) == 7 && strcmp(out, "machine") == 0);
	assert(wbx_setting_long("scale", 0) == 3);
	assert(wbx_setting_bool("fast", 0) == 1);
	assert(wbx_setting_str("naomi", out, sizeof out) == -1);   /* a value is not a key */

	/* wide whole numbers, as Chimera writes them (chimera#358): a ulong past
	 * a long, and the ends of a long, uint and datetime */
	const char *wide = "{\"seed\":18446744073709551615,\"low\":-9223372036854775808,\"uint\":4294967295,\"clock\":253402300799}";
	wbx_settings_use_buffer(wide, (int)strlen(wide));
	assert(wbx_setting_ulong("seed", 0) == 18446744073709551615ULL);
	assert(wbx_setting_ulong("absent", 7) == 7);
	if (sizeof(long) == 8) {   /* a guest's long; a 32-bit host long cannot hold these */
		assert(wbx_setting_long("low", 0) == (-9223372036854775807L - 1));
		assert(wbx_setting_long("uint", 0) == 4294967295L);
		assert(wbx_setting_long("clock", 0) == 253402300799L);
	}
	wbx_settings_use_file();
	puts("test_settings: ok");
	return 0;
}
