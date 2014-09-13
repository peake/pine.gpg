dnl
dnl Copyright (C) 2004-2014  Calvin E. Peake, Jr. <cp@absolutedigital.net>
dnl
dnl This file is part of PINE.GPG.
dnl
dnl PINE.GPG is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License version 2 as
dnl published by the Free Software Foundation.
dnl
dnl PINE.GPG is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
dnl LICENSE file distributed with PINE.GPG for more details.
dnl
dnl Process this file with autoconf to produce a configure script.

AC_INIT([PINE.GPG],
	[1.3.0],
	[cp@absolutedigital.net],
	[pine.gpg],
	[http://www.absolutedigital.net/projects/pine.gpg/])

RELEASE_DATE="13 Sep 2014"

AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_SRCDIR([src/pinegpg.c])

AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

AC_PROG_CC

AC_ARG_WITH([gpg],
	    [AS_HELP_STRING([--with-gpg=PATH],
			    [absolute path to the GPG binary])],
	    [AC_CHECK_FILE([$withval],
			   [gpg_path=$withval],
			   [AC_MSG_ERROR([supplied GPG binary does not exist: $withval])])],
	    [AC_PATH_PROG([gpg_path], [gpg])])

AC_DEFINE_UNQUOTED([GPG_PATH], ["$gpg_path"], [Absolute path of gpg(1)])

AC_SUBST(RELEASE_DATE)

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile doc/pine.gpg.1])
AC_OUTPUT
