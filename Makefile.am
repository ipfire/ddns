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

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory
AUTOMAKE_OPTIONS = color-tests

# remove target it the command fails
.DELETE_ON_ERROR:

# keep itermediate files
.SECONDARY:

SUBDIRS = . po

pythondir  = $(pyexecdir)

configsdir = $(sysconfdir)/ddns

CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST =

@INTLTOOL_POLICY_RULE@

.PHONY: update-po
update-po:
	$(MAKE) -C po update-po

# ------------------------------------------------------------------------------

dist_doc_DATA = \
	COPYING

# ------------------------------------------------------------------------------

bin_SCRIPTS = \
	ddns

EXTRA_DIST += \
	ddns.in

CLEANFILES += \
	ddns

dist_configs_DATA = \
	ddns.conf.sample

ddns_PYTHON = \
	src/ddns/__init__.py \
	src/ddns/__version__.py \
	src/ddns/errors.py \
	src/ddns/i18n.py \
	src/ddns/providers.py \
	src/ddns/system.py

ddnsdir = $(pythondir)/ddns

# ------------------------------------------------------------------------------

substitutions = \
	'|PACKAGE_NAME=$(PACKAGE_NAME)|' \
	'|PACKAGE_VERSION=$(PACKAGE_VERSION)|' \
	'|configsdir=$(configsdir)|'

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) $(subst '|,-e 's|@,$(subst =,\@|,$(subst |',|g',$(substitutions)))) \
		< $< > $@

ddns: ddns.in Makefile
	$(SED_PROCESS)
