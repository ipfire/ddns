###############################################################################
#                                                                             #
# Pakfire - The IPFire package management system                              #
# Copyright (C) 2013 Pakfire development team                                 #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

AC_PREREQ([2.64])

AC_INIT([ddns],
	[003],
	[info@ipfire.org],
	[ddns],
	[http://git.ipfire.org/?p=oddments/ddns.git;a=summary])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_PREFIX_DEFAULT([/usr])

AM_INIT_AUTOMAKE([
	foreign
	1.11
	-Wall
	-Wno-portability
	silent-rules
	tar-pax
	subdir-objects
])
AM_SILENT_RULES([yes])

IT_PROG_INTLTOOL([0.40.0])

GETTEXT_PACKAGE=ddns
AC_SUBST(GETTEXT_PACKAGE)

AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED

# Python
AM_PATH_PYTHON([2.7])

# BIND nsupdate
AC_CHECK_TOOL([NSUPDATE], [nsupdate])
if test -z "${NSUPDATE}"; then
	AC_MSG_ERROR([*** nsupdate not found])
fi

save_LIBS="$LIBS"

AC_CONFIG_FILES([
	Makefile
	po/Makefile.in
	src/ddns/__version__.py
])

AC_OUTPUT
AC_MSG_RESULT([
	${PACKAGE_NAME} ${VERSION}

	prefix            : ${prefix}
	sysconfdir        : ${sysconfdir}

	nsupdate          : ${NSUPDATE}
])
