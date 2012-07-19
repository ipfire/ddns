#!/usr/bin/python

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

