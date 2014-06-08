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


class DDNSConfigurationError(DDNSError):
	"""
		Thrown when invalid or insufficient
		data is provided by the configuration file.
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
