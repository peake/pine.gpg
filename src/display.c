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
 * display.c - Display filter.
 * created 27 Jul 2004
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "pinegpg.h"
#include "utility.h"

/**
 * Decrypt and/or verify a PGP message.
 *
 * @param  input        The data to decrypt/verify.
 * @param  input_len    The size of the data in bytes.
 * @param  f            The file descriptor of our input-turned-output file.
 * @param  result_file  The path to our result file or NULL if none.
 * @param  gpg          The path to the gpg(1) binary.
 * @param  gpg_args     A list of arguments to be passed to gpg(1).
 * @return              Nothing.
 */
static void decrypt_message(const char *input, const int input_len,
			    const int f, const char *result_file,
			    const char *gpg, char * const *gpg_args)
{
	int i, s;
	int pin[2], pout[2], perr[2];
	static const int buf_size = BUF_SIZE;
	pid_t pid[2];
	char buf[buf_size], errmsg[64];
	ssize_t bytes, bytes_read, total;

	static const char *trl = "--[PINE.GPG]----------------------------"
				 "---------------------------------[TOP]--\n",
			  *grl = "--[PINE.GPG]----------------------------"
				 "---------------------------------[GPG]--\n",
			  *erl = "--[PINE.GPG]----------------------------"
				 "---------------------------------[END]--\n";

	if (pipe(pin) == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to create pipe for stdin");

	pid[0] = fork();
	if (pid[0] == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to create fork for feeder sub-process");

	if (pid[0] == 0) {
		close(pin[0]);

		total = 0;
		while ((bytes = write(pin[1], input + total,
				      input_len - total)) != 0) {
			if (bytes == -1) {
				if (errno == EINTR)
					continue;
				else
					die_x(127, errno, result_file,
					      "Feeder sub-process write error");
			}
			total += bytes;
		}

		close(pin[1]);

		if (total != input_len)
			die_x(127, 0, result_file, "Feeder sub-process bytes "
			      "wrote (%d) does not match input message size "
			      "(%d)", total, input_len);

		exit(EXIT_SUCCESS);
	}

	close(pin[1]);

	if (pipe(pout) == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to create pipe for stdout");

	if (pipe(perr) == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to create pipe for stderr");

	pid[1] = fork();
	if (pid[1] == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to create fork for GPG");

	if (pid[1] == 0) {
		close(pout[0]);
		close(perr[0]);

		if (dup2(pin[0], 0) == -1)  /* stdin read from feeder */
			die_x(EXIT_FAILURE, errno, result_file,
			      "Failed to reassign GPG stdin to pipe");

		if (dup2(pout[1], 1) == -1) /* stdout write to parent */
			die_x(EXIT_FAILURE, errno, result_file,
			      "Failed to reassign GPG stdout to pipe");

		if (dup2(perr[1], 2) == -1) /* stderr write to parent */
			die_x(EXIT_FAILURE, errno, result_file,
			      "Failed to reassign GPG stderr to pipe");

		execv(gpg, gpg_args);

		die_x(127, errno, result_file, "Failed to execv(%s)", gpg);
	}

	close(pout[1]);
	close(perr[1]);

	if (mlock(&buf, buf_size) == -1)
		die_x(EXIT_FAILURE, errno, result_file,
		      "Failed to lock read buffer memory");

	total = 0;
	while ((bytes = write(f, trl + total, strlen(trl) - total)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, result_file,
				      "Input file write error");
		}
		total += bytes;
	}

	while ((bytes_read = read(pout[0], &buf, buf_size)) != 0) {
		if (bytes_read == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, result_file,
				      "GPG stdout read error");
		}

		total = 0;
		while ((bytes = write(f, buf + total,
				      bytes_read - total)) != 0) {
			if (bytes == -1) {
				if (errno == EINTR)
					continue;
				else
					die_x(EXIT_FAILURE, errno, result_file,
					      "Input file write error");
			}
			total += bytes;
		}
	}

	total = 0;
	while ((bytes = write(f, grl + total, strlen(grl) - total)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, result_file,
				      "Input file write error");
		}
		total += bytes;
	}

	while ((bytes_read = read(perr[0], &buf, buf_size)) != 0) {
		if (bytes_read == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, result_file,
				      "GPG stderr read error");
		}

		total = 0;
		while ((bytes = write(f, buf + total,
				      bytes_read - total)) != 0) {
			if (bytes == -1) {
				if (errno == EINTR)
					continue;
				else
					die_x(EXIT_FAILURE, errno, result_file,
					      "Input file write error");
			}
			total += bytes;
		}
	}

	/* Write these errors to the output file so that the user can see them.
	 * If we terminate with EXIT_FAILURE, then the MUA will not show any
	 * filtered text and the user will not be able to see the problem.
	 */
	for (i = 0; i < 2; i++) {
		do {
			while (waitpid(pid[i], &s, 0) == -1) {
				if (errno == EINTR)
					continue;
				else {
					snprintf(errmsg, sizeof (errmsg),
						 "  [PINE.GPG] Failed to reap "
						 "%s child process %d\n",
						 (i ? "GPG" : "feeder"),
						 pid[i]);
					write(f, errmsg, strlen(errmsg));
				}
			}
		} while (!WIFEXITED(s) && !WIFSIGNALED(s));

		if (WIFSIGNALED(s) && WTERMSIG(s)) {
			snprintf(errmsg, sizeof (errmsg),
				 "  [PINE.GPG] %s terminated by signal %d\n",
				 (i ? "GPG process" : "Feeder sub-process"),
				 WTERMSIG(s));
			write(f, errmsg, strlen(errmsg));
		}

		/* GPG exits with a status of one (1) if signature
		 * verification fails.  A status of greater than one (1)
		 * indicates a "real" error.
		 */
		if ((i == 0 && WEXITSTATUS(s) > 0) ||
		    (i == 1 && WEXITSTATUS(s) > 1)) {
			snprintf(errmsg, sizeof (errmsg),
				 "  [PINE.GPG] %s exited with status %d\n",
				 (i ? "GPG process" : "Feeder sub-process"),
				 WEXITSTATUS(s));
			write(f, errmsg, strlen(errmsg));
		}
	}

	total = 0;
	while ((bytes = write(f, erl + total, strlen(erl) - total)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, result_file,
				      "Input file write error");
		}
		total += bytes;
	}
}

/**
 * Display filter for decrypting and/or verifying signatures.
 *
 * @param  config  The program configuration.
 * @return         Nothing.
 */
void display(const pinegpg_config *config)
{
	int f;
	int arg_idx = 0, nr_args = 6;
	int pgp_begin_len, pgp_end_len, pgp_len;
	int pgp_msg_begin_len, pgp_msg_end_len, pgp_msg_len;
	int pgp_signed_begin_len, pgp_signed_end_len, pgp_signed_len;
	const char *e, *p, *pb, *pe, *pl;
	const char *pgp_begin, *pgp_end;
	char **gpg_args, *gpg, *input;
	ssize_t bytes, total, input_size;
	struct stat sbuf;

	const char *result_ok    = "Display filter completed successfully.",
		   *result_empty = "Display filter skipped empty input.";

	const char *pgp_msg_begin    = "-----BEGIN PGP MESSAGE-----\n",
		   *pgp_msg_end      = "-----END PGP MESSAGE-----\n",
		   *pgp_signed_begin = "-----BEGIN PGP SIGNED MESSAGE-----\n",
		   *pgp_signed_end   = "-----END PGP SIGNATURE-----\n";

	pgp_msg_begin_len = strlen(pgp_msg_begin);
	pgp_msg_end_len   = strlen(pgp_msg_end);
	pgp_msg_len       = pgp_msg_begin_len + pgp_msg_end_len;

	pgp_signed_begin_len = strlen(pgp_signed_begin);
	pgp_signed_end_len   = strlen(pgp_signed_end);
	pgp_signed_len       = pgp_signed_begin_len + pgp_signed_end_len;

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

	if (config->verbose > 0)
		gpg_args[arg_idx++] = "--verbose";

	if (config->verbose > 1)
		gpg_args[arg_idx++] = "--verbose";
	/*
	 * This should be --decrypt for both decryption and signature
	 * verification.  Using --verify does not print out the verified
	 * (and unescaped) data.
	 */
	gpg_args[arg_idx++] = "--decrypt";
	gpg_args[arg_idx++] = "-";
	gpg_args[arg_idx++] = NULL;

	if (stat(config->input_file, &sbuf) == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to get size of input file");

	input_size = sbuf.st_size;
	if (input_size == 0)
		die_x(EXIT_SUCCESS, 0, config->result_file, result_empty);

	input = malloc(sizeof (char) * input_size);
	if (input == NULL)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to allocate buffer for input file");

	f = open(config->input_file, O_RDWR);
	if (f == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to open input file for read/write");

	total = 0;
	while ((bytes = read(f, input + total, input_size - total)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "Input file read error");
		}
		total += bytes;
	}

	if (total != input_size)
		die_x(EXIT_FAILURE, 0, config->result_file,
		      "Bytes read (%d) does not match input file size (%d)",
		      total, input_size);

	if (lseek(f, 0, SEEK_SET) == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to seek to beginning of input file");

	if (ftruncate(f, 0) == -1)
		die_x(EXIT_FAILURE, errno, config->result_file,
		      "Failed to truncate input file");

	p = pe = pl = input;
	e = input + input_size;

	for (; p < e; p++) {
		if (*p != '-')
			continue;
		if ((p + pgp_signed_len) <= e &&
		    (p == input || *(p - 1) == '\n') &&
		    memcmp(p, pgp_signed_begin, pgp_signed_begin_len) == 0) {
			pgp_begin     = pgp_signed_begin;
			pgp_begin_len = pgp_signed_begin_len;
			pgp_end	      = pgp_signed_end;
			pgp_end_len   = pgp_signed_end_len;
			pgp_len       = pgp_signed_len;
		} else if ((p + pgp_msg_len) <= e &&
			   (p == input || *(p - 1) == '\n') &&
			   memcmp(p, pgp_msg_begin, pgp_msg_begin_len) == 0) {
			pgp_begin     = pgp_msg_begin;
			pgp_begin_len = pgp_msg_begin_len;
			pgp_end       = pgp_msg_end;
			pgp_end_len   = pgp_msg_end_len;
			pgp_len       = pgp_msg_len;
		} else
			continue;

		pb = p;
		p += pgp_begin_len;
		for (; p <= e; p++) {
			if (*p != '-')
				continue;
			if ((p + pgp_end_len) <= e &&
			    *(p - 1) == '\n' &&
			    memcmp(p, pgp_end, pgp_end_len) == 0) {
				while (pl != pb &&
				       (bytes = write(f, pl, pb - pl)) != 0) {
					if (bytes == -1) {
						if (errno == EINTR)
							continue;
						else
							die_x(EXIT_FAILURE,
							      errno,
							      config->result_file,
							      "Input file "
							      "write error");
					}
					pl += bytes;
				}
				p += pgp_end_len;
				pe = pl = p;
				decrypt_message(pb, p - pb, f,
						config->result_file,
						config->gpg, gpg_args);
				break;
			}
		}
	}

	while (pe != e && (bytes = write(f, pe, e - pe)) != 0) {
		if (bytes == -1) {
			if (errno == EINTR)
				continue;
			else
				die_x(EXIT_FAILURE, errno, config->result_file,
				      "Input file write error");
		}
		pe += bytes;
	}

	close(f);

	die_x(EXIT_SUCCESS, 0, config->result_file, result_ok);
}
