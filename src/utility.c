/*
 * Copyright (C) 2004-2014  Calvin E. Peake, Jr. <cp@absolutedigital.net>
 *
 * This file is part of PINE.GPG.
 *
 * PINE.GPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * PINE.GPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * LICENSE file distributed with PINE.GPG for more details.
 *
 * utility.c - Utility functions.
 * created 27 Jul 2004
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

/**
 * Print an error message to the result file if available, or stderr if not,
 * then terminate the program with the supplied status.
 *
 * @param  status  The status to pass to exit(3).
 * @param  errnum  If a non-zero value, then add strerror(3) to output.
 * @param  result  The path to the result file.
 * @param  format  A printf(3)-style format string.
 * @param  ...     A variable number of arguments for the format string.
 * @return         Nothing.
 */
void die_x(int status, int errnum, const char *result, const char *format, ...)
{
	int f, use_result = 0;
	va_list va;

	if (result != NULL) {
		f = open(result, O_WRONLY | O_CREAT | O_APPEND,
			 S_IRUSR | S_IWUSR);
		if (f != -1) {
			if (dup2(f, 2) == -1) {
				close(f);
				unlink(result);
			} else
				use_result = 1;
		}
	}

	if (!use_result) {
		fflush(stdout);
		fprintf(stderr, "  ");
	}

	fprintf(stderr, "[PINE.GPG] ");

	va_start(va, format);
	vfprintf(stderr, format, va);
	va_end(va);

	if (errnum != 0)
		fprintf(stderr, ": %s", strerror(errnum));

	fprintf(stderr, "\n");

	if (!use_result && status && status != 127) {
		fprintf(stderr, "\n  [PINE.GPG] Press ENTER to exit.");
		getchar();
	}

	exit(status);
}
