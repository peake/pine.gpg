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
 * sending.c - Sending filter.
 * created 27 Jul 2004
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "pinegpg.h"
#include "utility.h"

/**
 * Sending filter for encrypting and/or signing.
 *
 * @param  config  The program configuration.
 * @return         Nothing.
 */
void sending(const pinegpg_config *config)
{
	int f, i, s, pout[2];
	int arg_idx = 0, nr_args = 14 + config->nr_rcpts * 2;
	pid_t pid;
	ssize_t bytes, wrote = 0, total = 0, gpg_out_size = BUF_SIZE;
	const size_t buf_size = gpg_out_size;
	char buf[buf_size], resp;
	char **gpg_args, *gpg_out, *gpg, *p;
	struct termios termio, termio_orig;

	const char *result_ok    = "Sending filter completed successfully.",
		   *result_abort = "Sending filter aborted.";

	gpg_args = malloc(sizeof (char *) * nr_args);
	if (gpg_args == NULL)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to create array for GPG arguments list");

	p = strrchr(config->gpg, '/');
	if (p == NULL)
		p = config->gpg;
	else
		p++;

	gpg = strdup(p);
	if (gpg == NULL)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to allocate memory for GPG process name");

	gpg_args[arg_idx++] = gpg;
	gpg_args[arg_idx++] = "--armor";
	gpg_args[arg_idx++] = "--set-filename";
	gpg_args[arg_idx++] = "";
	gpg_args[arg_idx++] = "--output";
	gpg_args[arg_idx++] = "-";

	if (config->default_key != NULL) {
		gpg_args[arg_idx++] = "--default-key";
		gpg_args[arg_idx++] = config->default_key;
	}

	if (config->verbose > 0)
		gpg_args[arg_idx++] = "--verbose";

	if (config->verbose > 1)
		gpg_args[arg_idx++] = "--verbose";

	switch (config->mode) {
	case sending_mode:
		if (tcgetattr(0, &termio) == -1)
			die_x(EXIT_FAILURE, errno, config->result_file,
			      "Failed to get terminal attributes");

		memcpy(&termio_orig, &termio, sizeof (struct termios));

		termio.c_lflag    &= ~ICANON;
		termio.c_cc[VMIN]  = 1;
		termio.c_cc[VTIME] = 0;

		if (tcsetattr(0, TCSANOW, &termio) == -1)
			die_x(EXIT_FAILURE, errno, config->result_file,
			      "Failed to set terminal attributes");

		for (i = 0; i < 1;) {
			printf("\n"
			       "  [PINE.GPG] (S)ign, (E)ncrypt, (B)oth, or "
			       "(A)bort (s/e/b/a)? ");
			resp = getchar();
			switch (resp) {
				case 's': case 'e': case 'b': case 'a': i++;
			}
		}
		printf("\n");

		if (tcsetattr(0, TCSANOW, &termio_orig) == -1)
			die_x(EXIT_FAILURE, errno, config->result_file,
			      "Failed to restore terminal attributes");
		break;
	case sign_mode:    resp = 's'; break;
	case encrypt_mode: resp = 'e'; break;
	case both_mode:    resp = 'b'; break;
	default:	   resp = 'a'; break;
	}

	switch (resp) {
	case 'a':
		die_x(EXIT_FAILURE, 0, config->result_file, result_abort);
	case 's':
		gpg_args[arg_idx++] = "--clearsign";
		break;
	case 'b':
		gpg_args[arg_idx++] = "--sign";
	case 'e':
		gpg_args[arg_idx++] = "--encrypt";
		for (i = 0; i < config->nr_rcpts; i++) {
			gpg_args[arg_idx++] = "--recipient";
			gpg_args[arg_idx++] = config->rcpts[i];
		}
	}

	gpg_args[arg_idx++] = config->input_file;
	gpg_args[arg_idx++] = NULL;

	if (pipe(pout) == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to create pipe for stdout");

	pid = fork();
	if (pid == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to create fork for GPG");

	if (pid == 0) {
		close(pout[0]);

		if (dup2(pout[1], 1) == -1)
			die_x(EXIT_FAILURE, errno, config->result_file,
			      "Failed to reassign GPG stdout to pipe");

		execv(config->gpg, gpg_args);

		die_x(127, errno, config->result_file, "Failed to execv(%s)",
		      config->gpg);
	}

	close(pout[1]);

	gpg_out = malloc(sizeof (char) * gpg_out_size);
	if (gpg_out == NULL)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to allocate buffer for GPG output");

	p = gpg_out;
	while ((bytes = read(pout[0], &buf, buf_size)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "GPG stdout read error");
		}

		while ((bytes + total) >= gpg_out_size) {
			gpg_out_size += buf_size;
			gpg_out = realloc(gpg_out,
					  sizeof (char) * gpg_out_size);
			if (gpg_out == NULL)
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "Failed to increase GPG output buffer "
				      "size");
			if (gpg_out_size > (bytes + total))
				p = gpg_out + total;
		}

		memcpy(p, &buf, bytes);
		total += bytes;
		p += bytes;
	}

	do {
		while (waitpid(pid, &s, 0) == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "Failed to reap GPG child process %d",
				      pid);
		}
	} while (!WIFEXITED(s) && !WIFSIGNALED(s));

	if (WIFSIGNALED(s) && WTERMSIG(s))
		die_x(EXIT_FAILURE, 0, config->result_file,
		      "GPG process terminated by signal %d", WTERMSIG(s));

	if (WEXITSTATUS(s) > 0)
		die_x(EXIT_FAILURE, 0, config->result_file,
		      "GPG process exited with status %d", WEXITSTATUS(s));

	f = open(config->input_file, O_WRONLY | O_TRUNC);
	if (f == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to open input file for writing");

	while ((bytes = write(f, gpg_out + wrote, total - wrote)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "Input file write error");
		}
		wrote += bytes;
	}

	if (total != wrote)
		die_x(EXIT_FAILURE, 0, config->result_file,
		      "Bytes wrote (%d) does not match output buffer size (%d)",
		      wrote, total);

	close(f);

	die_x(EXIT_SUCCESS, 0, config->result_file, result_ok);
}
