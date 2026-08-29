/* diag.c - saying what happened when the sandbox dies.
 *
 * A guest death is not like other bugs: there is no core dump to read, no
 * debugger attached, and often no console. On Windows the host is loaded into a
 * GUI process, so stderr goes precisely nowhere - which turns "the guest hit an
 * unimplemented syscall at frame 3" into "the emulator vanished", and the person
 * who could have fixed it in five minutes gets nothing to work from.
 *
 * So a FATAL diagnostic also goes to a file. Only fatal ones: this writes
 * nothing during a normal run, and the file appearing at all means something
 * died. MINIBOX_LOG names it; otherwise it lands beside the working directory as
 * minibox-diag.log.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "minibox_internal.h"

static const char *diag_path(void) {
	const char *env = getenv("MINIBOX_LOG");
	return (env != NULL && *env != '\0') ? env : "minibox-diag.log";
}

void mb_diag(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);

	/* Appended, not truncated: a second failure after the first is a fact worth
	 * keeping, and the file is small. */
	FILE *f = fopen(diag_path(), "a");
	if (f == NULL) return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

void mb_diag_banner(const char *what) {
	time_t now = time(NULL);
	char stamp[32];
	struct tm *tm = localtime(&now);
	if (tm == NULL || strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", tm) == 0) stamp[0] = '\0';
	mb_diag("\n=== miniBox: %s (%s) ===\n", what, stamp);
}

/* ---- provenance ----
 * What this library was built from, for the frontend to show and a movie to record.
 * The whole emulation path is meant to be reproducible from what an artifact carries;
 * the host was the last part of it that could not say where it came from.
 *
 * The values arrive as compile-time defines because two build systems compile these
 * sources (miniBox's own, and Chimera's, which lists them itself), and a define is
 * the one thing both can supply without sharing a generated file. Everything here is
 * a function of the inputs - no timestamps, no hostname, no paths - so that two
 * builds of one commit stay byte-identical.
 */
#ifndef MB_BUILD_COMMIT
#define MB_BUILD_COMMIT "unknown"
#endif
#ifndef MB_BUILD_COMPILER
#define MB_BUILD_COMPILER "unknown"
#endif
#ifndef MB_BUILD_OS
#define MB_BUILD_OS "unknown"
#endif

const char *mb_build_info(void) {
	return "{\"component\":\"miniBox host\""
	       ",\"commit\":\"" MB_BUILD_COMMIT "\""
	       ",\"compiler\":\"" MB_BUILD_COMPILER "\""
	       ",\"builtOn\":\"" MB_BUILD_OS "\""
#if defined(_WIN32)
	       ",\"target\":\"windows-x86_64\""
#else
	       ",\"target\":\"linux-x86_64\""
#endif
	       "}";
}
