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

N_ = lambda x: x

class DDNSError(Exception):
	"""
		Generic error class for all exceptions
		raised by DDNS.
	"""
	reason = N_("Error")

	def __init__(self, message=None):
		self.message = message


class DDNSNetworkError(DDNSError):
	"""
		Thrown when a network error occured.
	"""
	reason = N_("Network error")


class DDNSAbuseError(DDNSError):
	"""
		Thrown when the server reports
		abuse for this account.
	"""
	reason = N_("The server denied processing the request because account abuse is suspected")


class DDNSAuthenticationError(DDNSError):
	"""
		Thrown when the server did not
		accept the user credentials.
	"""
	reason = N_("Authentication against the server has failed")


class DDNSBlockedError(DDNSError):
	"""
		Thrown when the dynamic update client
		(specified by the user-agent) has been blocked
		by a dynamic DNS provider.
	"""
	reason = N_("The server denies any updates from this client")


class DDNSCertificateError(DDNSError):
	"""
		Thrown when a server presented an invalid certificate.
	"""
	reason = N_("Invalid certificate")


class DDNSConfigurationError(DDNSError):
	"""
		Thrown when invalid or insufficient
		data is provided by the configuration file.
	"""
	reason = N_("The configuration file has errors")


class DDNSConnectionRefusedError(DDNSNetworkError):
	"""
		Thrown when a connection is refused.
	"""
	reason = N_("Connection refused")


class DDNSConnectionTimeoutError(DDNSNetworkError):
	"""
		Thrown when a connection to a server has timed out.
	"""
	reason = N_("Connection timeout")


class DDNSHostNotFoundError(DDNSError):
	"""
		Thrown when a configuration entry could
		not be found.
	"""
	reason = N_("The host could not be found in the configuration file")


class DDNSInternalServerError(DDNSError):
	"""
		Thrown when the remote server reported
		an error on the provider site.
	"""
	reason = N_("Internal server error")


class DDNSNetworkUnreachableError(DDNSNetworkError):
	"""
		Thrown when a network is not reachable.
	"""
	reason = N_("Network unreachable")


class DDNSNoRouteToHostError(DDNSNetworkError):
	"""
		Thrown when there is no route to a host.
	"""
	reason = N_("No route to host")


class DDNSNotFound(DDNSError):
	"""
		Thrown when the called URL has not been found
	"""
	reason = N_("Not found")


class DDNSRequestError(DDNSError):
	"""
		Thrown when a request could
		not be properly performed.
	"""
	reason = N_("Request error")


class DDNSResolveError(DDNSNetworkError):
	"""
		Thrown when a DNS record could not be resolved
		because of a local error.
	"""
	reason = N_("Could not resolve DNS entry")


class DDNSSSLError(DDNSNetworkError):
	"""
		Raised when a SSL connection could not be
		negotiated.
	"""
	reason = N_("SSL negotiation error")


class DDNSServiceUnavailableError(DDNSNetworkError):
	"""
		Equivalent to HTTP error code 503.
	"""
	reason = N_("Service unavailable")


class DDNSUpdateError(DDNSError):
	"""
		Thrown when an update could not be
		properly performed.
	"""
	reason = N_("The update could not be performed")
