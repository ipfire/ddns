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
INSTALL_DIRS =
noinst_DATA =

@INTLTOOL_POLICY_RULE@

.PHONY: update-po
update-po:
	$(MAKE) -C po update-po

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

# ------------------------------------------------------------------------------

AM_V_XSLT   = $(AM_V_XSLT_$(V))
AM_V_XSLT_  = $(AM_V_XSLT_$(AM_DEFAULT_VERBOSITY))
AM_V_XSLT_0 = @echo "  XSLT    " $@;

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
	src/ddns/database.py \
	src/ddns/errors.py \
	src/ddns/i18n.py \
	src/ddns/providers.py \
	src/ddns/system.py

ddnsdir = $(pythondir)/ddns

# ------------------------------------------------------------------------------

if ENABLE_MANPAGES
MANPAGES = \
	man/ddns.1 \
	man/ddns.conf.5

MANPAGES_XML  = $(patsubst %.1,%.xml,$(patsubst %.5,%.xml,$(MANPAGES)))
MANPAGES_HTML = $(patsubst %.xml,%.html,$(MANPAGES_XML))

man: $(MANPAGES) $(MANPAGES_HTML)

man_MANS = \
	$(MANPAGES)

noinst_DATA += \
	$(MANPAGES_HTML)

CLEANFILES += \
	$(man_MANS) \
	$(MANPAGES_HTML)

EXTRA_DIST += \
	$(MANPAGES_XML) \
	man/custom-html.xsl

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 1 \
	--stringparam man.copyright.section.enabled 1

XSLTPROC_COMMAND_MAN = \
	$(AM_V_XSLT)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) \
		http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

XSLTPROC_COMMAND_HTML = \
	$(AM_V_XSLT)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) $(srcdir)/man/custom-html.xsl $<

man/%.1: man/%.xml
	$(XSLTPROC_COMMAND_MAN)

man/%.5: man/%.xml
	$(XSLTPROC_COMMAND_MAN)

man/%.html: man/%.xml man/custom-html.xsl
	$(XSLTPROC_COMMAND_HTML)

endif

# ------------------------------------------------------------------------------

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	src/systemd/ddns.service \
	src/systemd/ddns.timer

CLEANFILES += \
	$(systemdsystemunit_DATA)

INSTALL_DIRS += \
	$(systemdsystemunitdir)
endif

EXTRA_DIST += \
	src/systemd/ddns.service.in \
	src/systemd/ddns.timer

# ------------------------------------------------------------------------------

substitutions = \
	'|PACKAGE_NAME=$(PACKAGE_NAME)|' \
	'|PACKAGE_VERSION=$(PACKAGE_VERSION)|' \
	'|configsdir=$(configsdir)|' \
	'|bindir=$(bindir)|'

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
	$(SED) $(subst '|,-e 's|@,$(subst =,\@|,$(subst |',|g',$(substitutions)))) \
		< $< > $@

ddns: ddns.in Makefile
	$(SED_PROCESS)

src/systemd/%: src/systemd/%.in Makefile
	$(SED_PROCESS)
