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

import base64
import re
import socket
import urllib
import urllib2

from __version__ import CLIENT_VERSION
from .errors import *
from i18n import _

# Initialize the logger.
import logging
logger = logging.getLogger("ddns.system")
logger.propagate = 1

class DDNSSystem(object):
	"""
		The DDNSSystem class adds a layer of abstraction
		between the ddns software and the system.
	"""

	# The default useragent.
	USER_AGENT = "IPFireDDNSUpdater/%s" % CLIENT_VERSION

	def __init__(self, core):
		# Connection to the core of the program.
		self.core = core

	@property
	def proxy(self):
		proxy = self.core.settings.get("proxy")

		# Strip http:// at the beginning.
		if proxy and proxy.startswith("http://"):
			proxy = proxy[7:]

		return proxy

	def _guess_external_ip_address(self, url, timeout=10):
		"""
			Sends a request to an external web server
			to determine the current default IP address.
		"""
		try:
			response = self.send_request(url, timeout=timeout)

		# If the server could not be reached, we will return nothing.
		except DDNSNetworkError:
			return

		if not response.code == 200:
			return

		match = re.search(r"^Your IP address is: (.*)$", response.read())
		if match is None:
			return

		return match.group(1)

	def guess_external_ipv6_address(self):
		"""
			Sends a request to the internet to determine
			the public IPv6 address.
		"""
		return self._guess_external_ip_address("http://checkip6.dns.lightningwirelabs.com")

	def guess_external_ipv4_address(self):
		"""
			Sends a request to the internet to determine
			the public IPv4 address.
		"""
		return self._guess_external_ip_address("http://checkip4.dns.lightningwirelabs.com")

	def send_request(self, url, method="GET", data=None, username=None, password=None, timeout=30):
		assert method in ("GET", "POST")

		# Add all arguments in the data dict to the URL and escape them properly.
		if method == "GET" and data:
			query_args = self._format_query_args(data)
			data = None

			url = "%s?%s" % (url, query_args)

		logger.debug("Sending request (%s): %s" % (method, url))
		if data:
			logger.debug("  data: %s" % data)

		req = urllib2.Request(url, data=data)

		if username and password:
			basic_auth_header = self._make_basic_auth_header(username, password)
			print repr(basic_auth_header)
			req.add_header("Authorization", "Basic %s" % basic_auth_header)

		# Set the user agent.
		req.add_header("User-Agent", self.USER_AGENT)

		# All requests should not be cached anywhere.
		req.add_header("Pragma", "no-cache")

		# Set the upstream proxy if needed.
		if self.proxy:
			logger.debug("Using proxy: %s" % self.proxy)

			# Configure the proxy for this request.
			req.set_proxy(self.proxy, "http")

		assert req.get_method() == method

		logger.debug(_("Request header:"))
		for k, v in req.headers.items():
			logger.debug("  %s: %s" % (k, v))

		try:
			resp = urllib2.urlopen(req, timeout=timeout)

			# Log response header.
			logger.debug(_("Response header:"))
			for k, v in resp.info().items():
				logger.debug("  %s: %s" % (k, v))

			# Return the entire response object.
			return resp

		except urllib2.HTTPError, e:
			# 503 - Service Unavailable
			if e.code == 503:
				raise DDNSServiceUnavailableError

			# Raise all other unhandled exceptions.
			raise

		except urllib2.URLError, e:
			if e.reason:
				# Network Unreachable (e.g. no IPv6 access)
				if e.reason.errno == 101:
					raise DDNSNetworkUnreachableError
				elif e.reason.errno == 111:
					raise DDNSConnectionRefusedError

			# Raise all other unhandled exceptions.
			raise

		except socket.timeout, e:
			logger.debug(_("Connection timeout"))

			raise DDNSConnectionTimeoutError

	def _format_query_args(self, data):
		args = []

		for k, v in data.items():
			arg = "%s=%s" % (k, urllib.quote(v))
			args.append(arg)

		return "&".join(args)

	def _make_basic_auth_header(self, username, password):
		authstring = "%s:%s" % (username, password)

		# Encode authorization data in base64.
		authstring = base64.encodestring(authstring)

		# Remove any newline characters.
		authstring = authstring.replace("\n", "")

		return authstring

	def get_address(self, proto):
		assert proto in ("ipv6", "ipv4")

		# Check if the external IP address should be guessed from
		# a remote server.
		guess_ip = self.core.settings.get("guess_external_ip", "true")

		# If the external IP address should be used, we just do
		# that.
		if guess_ip in ("true", "yes", "1"):
			if proto == "ipv6":
				return self.guess_external_ipv6_address()

			elif proto == "ipv4":
				return self.guess_external_ipv4_address()

		# XXX TODO
		assert False

	def resolve(self, hostname, proto=None):
		addresses = []

		if proto is None:
			family = 0
		elif proto == "ipv6":
			family = socket.AF_INET6
		elif proto == "ipv4":
			family = socket.AF_INET
		else:
			raise ValueError("Protocol not supported: %s" % proto)

		# Resolve the host address.
		try:
			response = socket.getaddrinfo(hostname, None, family)
		except socket.gaierror, e:
			# Name or service not known
			if e.errno == -2:
				return []

			raise

		# Handle responses.
		for family, socktype, proto, canonname, sockaddr in response:
			# IPv6
			if family == socket.AF_INET6:
				address, port, flow_info, scope_id = sockaddr

				# Only use the global scope.
				if not scope_id == 0:
					continue

			# IPv4
			elif family == socket.AF_INET:
				address, port = sockaddr

			# Ignore everything else...
			else:
				continue

			# Add to repsonse list if not already in there.
			if not address in addresses:
				addresses.append(address)

		return addresses
