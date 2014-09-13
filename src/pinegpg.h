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
 * pinegpg.h - PINE.GPG entry point.
 * created 27 Jul 2004
 */

#ifndef PINEGPG_H
#define PINEGPG_H 1

#define BUF_SIZE 4096

typedef enum _program_mode {
	no_mode,
	display_mode,
	sending_mode,
	encrypt_mode,
	sign_mode,
	both_mode
} program_mode;

typedef struct _pinegpg_config {
	program_mode mode;
	char *input_file;
	char *result_file;
	char **rcpts;
	int  nr_rcpts;
	char *gpg;
	char *default_key;
	int  verbose;
} pinegpg_config;

#endif /* PINEGPG_H */
