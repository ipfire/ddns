#!/usr/bin/python3
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
import ssl
import socket
import urllib.request
import urllib.parse
import urllib.error

from .__version__ import CLIENT_VERSION
from .errors import *
from .i18n import _

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

		# Address cache.
		self.__addresses = {}

		# Find out on which distribution we are running.
		self.distro = self._get_distro_identifier()
		logger.debug(_("Running on distribution: %s") % self.distro)

	@property
	def proxy(self):
		proxy = self.core.settings.get("proxy")

		# Strip http:// at the beginning.
		if proxy and proxy.startswith("http://"):
			proxy = proxy[7:]

		return proxy

	def get_local_ip_address(self, proto):
		ip_address = self._get_local_ip_address(proto)

		# Check if the IP address is usable and only return it then
		if self._is_usable_ip_address(proto, ip_address):
			return ip_address

	def _get_local_ip_address(self, proto):
		# Legacy code for IPFire 2.
		if self.distro == "ipfire-2" and proto == "ipv4":
			try:
				with open("/var/ipfire/red/local-ipaddress") as f:
					return f.readline()

			except IOError as e:
				# File not found
				if e.errno == 2:
					return

				raise

		# XXX TODO
		raise NotImplementedError

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

		match = re.search(b"^Your IP address is: (.*)$", response.read())
		if match is None:
			return

		return match.group(1).decode()

	def guess_external_ip_address(self, family, **kwargs):
		if family == "ipv6":
			url = "https://checkip6.dns.lightningwirelabs.com"
		elif family == "ipv4":
			url = "https://checkip4.dns.lightningwirelabs.com"
		else:
			raise ValueError("unknown address family")

		return self._guess_external_ip_address(url, **kwargs)

	def send_request(self, url, method="GET", data=None, username=None, password=None, timeout=30):
		assert method in ("GET", "POST")

		# Add all arguments in the data dict to the URL and escape them properly.
		if method == "GET" and data:
			query_args = self._format_query_args(data)
			data = None

			if "?" in url:
				url = "%s&%s" % (url, query_args)
			else:
				url = "%s?%s" % (url, query_args)

		logger.debug("Sending request (%s): %s" % (method, url))
		if data:
			logger.debug("  data: %s" % data)

		req = urllib.request.Request(url, data=data)

		if username and password:
			basic_auth_header = self._make_basic_auth_header(username, password)
			req.add_header("Authorization", "Basic %s" % basic_auth_header.decode())

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
			resp = urllib.request.urlopen(req, timeout=timeout)

			# Log response header.
			logger.debug(_("Response header (Status Code %s):") % resp.code)
			for k, v in resp.info().items():
				logger.debug("  %s: %s" % (k, v))

			# Return the entire response object.
			return resp

		except urllib.error.HTTPError as e:
			# Log response header.
			logger.debug(_("Response header (Status Code %s):") % e.code)
			for k, v in e.hdrs.items():
				logger.debug("  %s: %s" % (k, v))

			# 400 - Bad request
			if e.code == 400:
				raise DDNSRequestError(e.reason)

			# 401 - Authorization Required
			# 403 - Forbidden
			elif e.code in (401, 403):
				raise DDNSAuthenticationError(e.reason)

			# 404 - Not found
			# Either the provider has changed the API, or
			# there is an error on the server
			elif e.code == 404:
				raise DDNSNotFound(e.reason)

			# 429 - Too Many Requests
			elif e.code == 429:
				raise DDNSTooManyRequests(e.reason)

			# 500 - Internal Server Error
			elif e.code == 500:
				raise DDNSInternalServerError(e.reason)

			# 503 - Service Unavailable
			elif e.code == 503:
				raise DDNSServiceUnavailableError(e.reason)

			# Raise all other unhandled exceptions.
			raise

		except urllib.error.URLError as e:
			if e.reason:
				# Handle SSL errors
				if isinstance(e.reason, ssl.SSLError):
					e = e.reason

					if e.reason == "CERTIFICATE_VERIFY_FAILED":
						raise DDNSCertificateError

					# Raise all other SSL errors
					raise DDNSSSLError(e.reason)

				# Name or service not known
				if e.reason.errno == -2:
					raise DDNSResolveError

				# Network Unreachable (e.g. no IPv6 access)
				if e.reason.errno == 101:
					raise DDNSNetworkUnreachableError

				# Connection Refused
				elif e.reason.errno == 111:
					raise DDNSConnectionRefusedError

				# No route to host
				elif e.reason.errno == 113:
					raise DDNSNoRouteToHostError(req.host)

			# Raise all other unhandled exceptions.
			raise

		except socket.timeout as e:
			logger.debug(_("Connection timeout"))

			raise DDNSConnectionTimeoutError

	def _format_query_args(self, data):
		args = []

		for k, v in data.items():
			arg = "%s=%s" % (k, urllib.parse.quote(v))
			args.append(arg)

		return "&".join(args)

	def _make_basic_auth_header(self, username, password):
		authstring = "%s:%s" % (username, password)

		# Encode authorization data in base64.
		authstring = base64.b64encode(authstring.encode())

		return authstring

	def get_address(self, proto):
		"""
			Returns the current IP address for
			the given IP protocol.
		"""
		try:
			return self.__addresses[proto]

		# IP is currently unknown and needs to be retrieved.
		except KeyError:
			self.__addresses[proto] = address = \
				self._get_address(proto)

			return address

	def _get_address(self, proto):
		assert proto in ("ipv6", "ipv4")

		# IPFire 2 does not support IPv6.
		if self.distro == "ipfire-2" and proto == "ipv6":
			return

		# Check if the external IP address should be guessed from
		# a remote server.
		guess_ip = self.core.settings.get("guess_external_ip", "true")
		guess_ip = guess_ip in ("true", "yes", "1")

		# Get the local IP address.
		local_ip_address = None

		if not guess_ip:
			try:
				local_ip_address = self.get_local_ip_address(proto)
			except NotImplementedError:
				logger.warning(_("Falling back to check the IP address with help of a public server"))

		# If no local IP address could be determined, we will fall back to the guess
		# it with help of an external server...
		if not local_ip_address:
			local_ip_address = self.guess_external_ip_address(proto)

		return local_ip_address

	def _is_usable_ip_address(self, proto, address):
		"""
			Returns True is the local IP address is usable
			for dynamic DNS (i.e. is not a RFC1918 address or similar).
		"""
		if proto == "ipv4":
			# This is not the most perfect solution to match
			# these addresses, but instead of pulling in an entire
			# library to handle the IP addresses better, we match
			# with regular expressions instead.
			matches = (
				# RFC1918 address space
				r"^10\.\d+\.\d+\.\d+$",
				r"^192\.168\.\d+\.\d+$",
				r"^172\.(1[6-9]|2[0-9]|31)\.\d+\.\d+$",

				# Dual Stack Lite address space
				r"^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d+\.\d+$",
			)

			for match in matches:
				m = re.match(match, address)
				if m is None:
					continue

				# Found a match. IP address is not usable.
				return False

		# In all other cases, return OK.
		return True

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
		except socket.gaierror as e:
			# Name or service not known
			if e.errno == -2:
				return []

			# Temporary failure in name resolution
			elif e.errno == -3:
				raise DDNSResolveError(hostname)

			# No record for requested family available (e.g. no AAAA)
			elif e.errno == -5:
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
			if address not in addresses:
				addresses.append(address)

		return addresses

	def _get_distro_identifier(self):
		"""
			Returns a unique identifier for the distribution
			we are running on.
		"""
		os_release = self.__parse_os_release()
		if os_release:
			return os_release

		system_release = self.__parse_system_release()
		if system_release:
			return system_release

		# If nothing else could be found, we return
		# just "unknown".
		return "unknown"

	def __parse_os_release(self):
		"""
			Tries to parse /etc/os-release and
			returns a unique distribution identifier
			if the file exists.
		"""
		try:
			f = open("/etc/os-release", "r")
		except IOError as e:
			# File not found
			if e.errno == 2:
				return

			raise

		os_release = {}
		with f:
			for line in f.readlines():
				m = re.match(r"^([A-Z\_]+)=(.*)$", line)
				if m is None:
					continue

				os_release[m.group(1)] = m.group(2)

		try:
			return "%(ID)s-%(VERSION_ID)s" % os_release
		except KeyError:
			return

	def __parse_system_release(self):
		"""
			Tries to parse /etc/system-release and
			returns a unique distribution identifier
			if the file exists.
		"""
		try:
			f = open("/etc/system-release", "r")
		except IOError as e:
			# File not found
			if e.errno == 2:
				return

			raise

		with f:
			# Read first line
			line = f.readline()

			# Check for IPFire systems
			m = re.match(r"^IPFire (\d).(\d+)", line)
			if m:
				return "ipfire-%s" % m.group(1)
