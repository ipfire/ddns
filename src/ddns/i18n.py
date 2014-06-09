#!/usr/bin/python
###############################################################################
#                                                                             #
# ddns - A dynamic DNS client for IPFire                                      #
# Copyright (C) 2012 IPFire development team                                  #
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

import gettext

TEXTDOMAIN = "ddns"

N_ = lambda x: x

def _(singular, plural=None, n=None):
	"""
		A function that returnes the translation of a string if available.

		The language is taken from the system environment.
        """
	if not plural is None:
		assert n is not None
		return gettext.dngettext(TEXTDOMAIN, singular, plural, n)

	return gettext.dgettext(TEXTDOMAIN, singular)

