/* waterbox_settings.h - miniBox guest kit: read the host's settings channel.
 *
 * The waterbox host (Chimera) mounts a file named "settings" holding this core's
 * effective settings - the package's waterbox.config defaults overlaid with the
 * user's sync settings - as a flat JSON object of scalar values, e.g.
 *     {"initFillByte": 171, "region": "ntsc", "turbo": true}
 * These helpers read scalar values by key during the guest's Init(). They return
 * the given default when the "settings" file or the key is absent, so a core that
 * ignores settings needs no special handling.
 *
 * C-only, header-only (parses with jsmn, MIT). C++ cores may prefer nlohmann/json
 * over this. v1 assumes a FLAT object of scalars.
 */
#ifndef WATERBOX_SETTINGS_H
#define WATERBOX_SETTINGS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSMN_STATIC
#include "jsmn.h"

#ifndef WBX_SETTINGS_MAX_BYTES
#define WBX_SETTINGS_MAX_BYTES 8192
#endif
#ifndef WBX_SETTINGS_MAX_TOKENS
#define WBX_SETTINGS_MAX_TOKENS 256
#endif

/* Copies the raw value text for `key` (for JSON strings, the unquoted content;
 * for numbers/bools, the literal) into `out`, NUL-terminated. Returns out on
 * success, or NULL if the file or key is absent. */
/* Where the next read comes from. Normally the mounted "settings" file, which
 * holds the settings this core was STARTED with. A host that supports live
 * (non-sync) settings hands over a fresh JSON buffer instead - see
 * wbx_settings_use_buffer below - because the mounted file is fixed for the
 * lifetime of the core and cannot carry a later change. */
/* One for the whole core, whichever source file asks: weak, so every file that
 * includes this shares the one definition. As statics each file had its own,
 * and a buffer handed over in PutSettings was not what another file read. */
__attribute__((weak)) const char *wbx__settings_override = 0;
__attribute__((weak)) int wbx__settings_override_len = 0;

/* Point subsequent wbx_setting_* reads at `json` instead of the mounted file.
 * Call from the core's PutSettings(len) export, read what you need, then call
 * wbx_settings_use_file() to go back. */
static inline void wbx_settings_use_buffer(const char *json, int len)
{
	wbx__settings_override = json;
	wbx__settings_override_len = len;
}

static inline void wbx_settings_use_file(void)
{
	wbx__settings_override = 0;
	wbx__settings_override_len = 0;
}

static inline const char *wbx__setting_raw(const char *key, char *out, int outsz)
{
	char buf[WBX_SETTINGS_MAX_BYTES];
	size_t n;
	if (wbx__settings_override) {
		n = (size_t)wbx__settings_override_len;
		if (n > sizeof buf - 1) n = sizeof buf - 1;
		memcpy(buf, wbx__settings_override, n);
	} else {
		FILE *f = fopen("settings", "rb");
		if (!f) return 0;
		n = fread(buf, 1, sizeof buf - 1, f);
		fclose(f);
	}
	buf[n] = 0;

	jsmn_parser p;
	jsmntok_t tok[WBX_SETTINGS_MAX_TOKENS];
	jsmn_init(&p);
	int r = jsmn_parse(&p, buf, n, tok, sizeof tok / sizeof tok[0]);
	if (r < 1 || tok[0].type != JSMN_OBJECT) return 0;

	/* flat object: OBJECT, then (key, value) pairs; the value is the token right
	 * after its key. Keys only: stepping one token at a time took a string
	 * VALUE equal to the key asked for as the key, and answered with the name
	 * of the setting after it. */
	size_t klen = strlen(key);
	for (int i = 1; i + 1 < r; i += 2) {
		if (tok[i + 1].type == JSMN_OBJECT || tok[i + 1].type == JSMN_ARRAY) return 0;   /* not flat */
		jsmntok_t *k = &tok[i];
		if (k->type == JSMN_STRING
			&& (size_t)(k->end - k->start) == klen
			&& strncmp(buf + k->start, key, klen) == 0) {
			jsmntok_t *v = &tok[i + 1];
			int vlen = v->end - v->start;
			if (vlen >= outsz) vlen = outsz - 1;
			memcpy(out, buf + v->start, (size_t)vlen);
			out[vlen] = 0;
			return out;
		}
	}
	return 0;
}

/* A whole number: Chimera's "int", "uint", "long" and "datetime" settings (a
 * datetime is its seconds since 1970, in UTC). A guest's long is 64 bits. */
static inline long wbx_setting_long(const char *key, long dflt)
{
	char v[64];
	return wbx__setting_raw(key, v, (int)sizeof v) ? strtol(v, 0, 0) : dflt;
}

/* A whole number of up to 64 bits with no sign: Chimera's "ulong" setting,
 * which may be past what a long holds (chimera#358). */
static inline unsigned long long wbx_setting_ulong(const char *key, unsigned long long dflt)
{
	char v[64];
	return wbx__setting_raw(key, v, (int)sizeof v) ? strtoull(v, 0, 10) : dflt;
}

static inline double wbx_setting_double(const char *key, double dflt)
{
	char v[64];
	return wbx__setting_raw(key, v, (int)sizeof v) ? strtod(v, 0) : dflt;
}

static inline int wbx_setting_bool(const char *key, int dflt)
{
	char v[16];
	if (!wbx__setting_raw(key, v, (int)sizeof v)) return dflt;
	return v[0] == 't' || v[0] == 'T' || (v[0] >= '1' && v[0] <= '9'); /* JSON true / nonzero */
}

/* Copies the string value for `key` into `out` (NUL-terminated). Returns the
 * length, or -1 if absent. */
static inline int wbx_setting_str(const char *key, char *out, int outsz)
{
	return wbx__setting_raw(key, out, outsz) ? (int)strlen(out) : -1;
}

#endif /* WATERBOX_SETTINGS_H */
