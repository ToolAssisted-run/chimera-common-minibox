/* waterbox_slots.h - miniBox guest kit: read the host's slot map.
 *
 * A chimera project mounts a file named "slots": a JSON object of slot id ->
 * canonical file names in swap order, each named file mounted under its own
 * name, e.g.
 *     {"floppy": ["a.img", "b.img"], "cdrom": ["game.iso"]}
 * The slot ids are the ones this core's file_slots.json declares (see
 * chimera's docs/project.md). These helpers read the map during the guest's
 * Init(); when the "slots" file is absent (a non-project host) they report
 * nothing, so a core keeps its legacy rom path as the fallback.
 *
 * C-only, header-only (parses with jsmn, MIT), same shape as
 * waterbox_settings.h.
 */
#ifndef WATERBOX_SLOTS_H
#define WATERBOX_SLOTS_H

#include <stdio.h>
#include <string.h>

#define JSMN_STATIC
#include "jsmn.h"

#ifndef WBX_SLOTS_MAX_BYTES
#define WBX_SLOTS_MAX_BYTES 8192
#endif
#ifndef WBX_SLOTS_MAX_TOKENS
#define WBX_SLOTS_MAX_TOKENS 512
#endif

/* Copies the name at `index` (0-based, slot order = swap order) of slot `id`
 * into `out`, NUL-terminated. Returns out, or NULL when the "slots" file,
 * the slot, or the index is absent. */
static inline const char *wbx_slot_name(const char *id, int index, char *out, int outsz)
{
	char buf[WBX_SLOTS_MAX_BYTES];
	size_t n;
	FILE *f = fopen("slots", "rb");
	if (!f) return 0;
	n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = 0;

	jsmn_parser p;
	jsmntok_t tok[WBX_SLOTS_MAX_TOKENS];
	jsmn_init(&p);
	int r = jsmn_parse(&p, buf, n, tok, sizeof tok / sizeof tok[0]);
	if (r < 1 || tok[0].type != JSMN_OBJECT) return 0;

	/* pairs of key + flat string array */
	int i = 1;
	int pair;
	for (pair = 0; pair < tok[0].size && i + 1 < r; pair++) {
		int klen = tok[i].end - tok[i].start;
		int match = tok[i].type == JSMN_STRING && (int)strlen(id) == klen
			&& memcmp(buf + tok[i].start, id, (size_t)klen) == 0;
		i++;
		if (tok[i].type != JSMN_ARRAY) { i++; continue; }
		int count = tok[i].size;
		i++;
		if (match) {
			if (index < 0 || index >= count) return 0;
			jsmntok_t *t = &tok[i + index];
			if (t->type != JSMN_STRING) return 0;
			int len = t->end - t->start;
			if (len >= outsz) len = outsz - 1;
			memcpy(out, buf + t->start, (size_t)len);
			out[len] = 0;
			return out;
		}
		i += count;
	}
	return 0;
}

/* The slot's first (or only) name - the common single-file case. */
static inline const char *wbx_slot_first(const char *id, char *out, int outsz)
{
	return wbx_slot_name(id, 0, out, outsz);
}

/* How many names slot `id` holds; 0 when the map or the slot is absent. */
static inline int wbx_slot_count(const char *id)
{
	char buf[WBX_SLOTS_MAX_BYTES];
	size_t n;
	FILE *f = fopen("slots", "rb");
	if (!f) return 0;
	n = fread(buf, 1, sizeof buf - 1, f);
	fclose(f);
	buf[n] = 0;

	jsmn_parser p;
	jsmntok_t tok[WBX_SLOTS_MAX_TOKENS];
	jsmn_init(&p);
	int r = jsmn_parse(&p, buf, n, tok, sizeof tok / sizeof tok[0]);
	if (r < 1 || tok[0].type != JSMN_OBJECT) return 0;

	int i = 1;
	int pair;
	for (pair = 0; pair < tok[0].size && i + 1 < r; pair++) {
		int klen = tok[i].end - tok[i].start;
		int match = tok[i].type == JSMN_STRING && (int)strlen(id) == klen
			&& memcmp(buf + tok[i].start, id, (size_t)klen) == 0;
		i++;
		if (tok[i].type != JSMN_ARRAY) { i++; continue; }
		int count = tok[i].size;
		if (match) return count;
		i += count + 1;
	}
	return 0;
}

#endif /* WATERBOX_SLOTS_H */
