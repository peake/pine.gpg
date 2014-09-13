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
 * pinegpg.c - PINE.GPG entry point.
 * created 27 Jul 2004
 * origin  21 Apr 2004
 */

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "pinegpg.h"
#include "display.h"
#include "sending.h"
#include "utility.h"

#include "config.h"

static const char *program_version = "1.3.0";

static void pr_usage(const char *program_name)
{
	printf("Usage: %s -d [-v...] [-r <file>] -i <file>\n"
	       "       %s -s [-v...] [-r <file>] -i <file> <recipient> "
	       "[<recipient>...]\n",
	       program_name, program_name);
}

static void exit_usage(const char *program_name)
{
	pr_usage(program_name);
	exit(EXIT_FAILURE); /* Always fail unless filtering completes OK. */
}

static void pr_version(void)
{
	printf("PINE.GPG %s\n"
	       "Copyright (C) 2004-2014  Calvin E. Peake, Jr.\n"
	       "Licensed under the GPLv2.\n", program_version);
}

static void exit_version(void)
{
	pr_version();
	exit(EXIT_FAILURE); /* Always fail unless filtering completes OK. */
}

static void pr_help(void)
{
	printf("\n"
"Options:\n"
"\n"
"  -d         Display filter mode: decrypt and/or verify.\n"
"  -s         Sending filter mode: encrypt and/or sign.\n"
"  -S         Sending filter mode: sign without prompting.\n"
"  -E         Sending filter mode: encrypt without prompting.\n"
"  -B         Sending filter mode: sign and encrypt without prompting.\n"
"  -i <file>  Input/output file.\n"
"  -r <file>  Result file for filtering status/errors.\n"
"  -g <path>  Specify an alternate path to the GPG binary.\n"
"  -k <key>   Specify the default signing key to use.\n"
"  -v         Have GPG be verbose in it's output.\n"
"  -h         Print program help (this screen) and exit.\n"
"  -V         Print program version and exit.\n"
	       "\n");
}

static void exit_help(const char *program_name)
{
	pr_version();
	pr_help();
	pr_usage(program_name);
	exit(EXIT_FAILURE); /* Always fail unless filtering completes OK. */
}

int main(int argc, char *argv[])
{
	char opt;
	struct rlimit limit;
	pinegpg_config config;

	config.mode = no_mode;
	config.input_file = NULL;
	config.result_file = NULL;
	config.rcpts = NULL;
	config.nr_rcpts = 0;
	config.gpg = GPG_PATH;
	config.default_key = NULL;
	config.verbose = 0;

	while ((opt = getopt(argc, argv, "BdEeg:hi:k:r:Sst:Vv")) != -1) {
		switch (opt) {
		case 'B':	/* sending filter, auto sign and encrypt */
			config.mode = both_mode;
			break;
		case 'd':	/* display filter (formerly decrypt) */
			config.mode = display_mode;
			break;
		case 'E':	/* sending filter, auto encrypt only */
			config.mode = encrypt_mode;
			break;
		case 'g':	/* gpg(1) */
			config.gpg = optarg;
			break;
		case 'h':	/* help */
			exit_help(argv[0]);
			break;
		case 'i':	/* input/output file */
			config.input_file = optarg;
			break;
		case 'k':	/* default key */
			config.default_key = optarg;
			break;
		case 'r':	/* result file */
			config.result_file = optarg;
			break;
		case 'S':	/* sending filter, auto sign only */
			config.mode = sign_mode;
			break;
		case 's':	/* sending filter */
		case 'e':	/* encrypt, deprecated */
			config.mode = sending_mode;
			break;
		case 't':	/* temporary directory, obsolete */
			break;
		case 'V':	/* program version */
			exit_version();
			break;
		case 'v':	/* gpg(1) verbose output */
			config.verbose++;
			break;
		default:
			exit_usage(argv[0]);
		}
	}

	if (config.input_file == NULL)
		exit_usage(argv[0]);

	if (optind < argc) {
		config.rcpts = malloc(sizeof (char *) * (argc - optind + 1));
		if (config.rcpts == NULL)
			die_x(EXIT_FAILURE, errno, config.result_file,
			      "Failed to create array for recipient list");

		for (; optind < argc; optind++, config.nr_rcpts++)
			config.rcpts[config.nr_rcpts] = argv[optind];
	}

	limit.rlim_cur = 0;
	limit.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &limit))
		die_x(EXIT_FAILURE, errno, config.result_file,
		      "Failed to disable core dumps");

	if (config.mode == display_mode)
		display(&config);
	else if (config.mode >= sending_mode && config.nr_rcpts > 0)
		sending(&config);
	else
		exit_usage(argv[0]);

	/* We should never reach this point, but we will default to fail
	 * anyway because we never want the possibility of an unfiltered
	 * message getting sent out.
	 */
	return 1;
}
