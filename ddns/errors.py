#!/usr/bin/python

class DDNSError(Exception):
	pass


class DDNSAbuseError(DDNSError):
	"""
		Thrown when the server reports
		abuse for this account.
	"""
	pass


class DDNSAuthenticationError(DDNSError):
	"""
		Thrown when the server did not
		accept the user credentials.
	"""
	pass


class DDNSInternalServerError(DDNSError):
	"""
		Thrown when the remote server reported
		an error on the provider site.
	"""
	pass


class DDNSRequestError(DDNSError):
	"""
		Thrown when a request could
		not be properly performed.
	"""
	pass


class DDNSUpdateError(DDNSError):
	"""
		Thrown when an update could not be
		properly performed.
	"""
	pass
