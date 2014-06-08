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

import re
import urllib2

from __version__ import CLIENT_VERSION
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

	def guess_external_ipv6_address(self):
		"""
			Sends a request to an external web server
			to determine the current default IP address.
		"""
		response = self.send_request("http://checkip6.dns.lightningwirelabs.com")

		if not response.code == 200:
			return

		match = re.search(r"^Your IP address is: (.*)$", response.read())
		if match is None:
			return

		return match.group(1)

	def guess_external_ipv4_address(self):
		"""
			Sends a request to the internet to determine
			the public IP address.

			XXX does not work for IPv6.
		"""
		response = self.send_request("http://checkip4.dns.lightningwirelabs.com")

		if response.code == 200:
			match = re.search(r"Your IP address is: (\d+.\d+.\d+.\d+)", response.read())
			if match is None:
				return

			return match.group(1)

	def send_request(self, url, data=None, timeout=30):
		logger.debug("Sending request: %s" % url)
		if data:
			logger.debug("  data: %s" % data)

		req = urllib2.Request(url, data=data)

		# Set the user agent.
		req.add_header("User-Agent", self.USER_AGENT)

		# All requests should not be cached anywhere.
		req.add_header("Pragma", "no-cache")

		# Set the upstream proxy if needed.
		if self.proxy:
			logger.debug("Using proxy: %s" % self.proxy)

			# Configure the proxy for this request.
			req.set_proxy(self.proxy, "http")

		logger.debug(_("Request header:"))
		for k, v in req.headers.items():
			logger.debug("  %s: %s" % (k, v))

		try:
			resp = urllib2.urlopen(req)

			# Log response header.
			logger.debug(_("Response header:"))
			for k, v in resp.info().items():
				logger.debug("  %s: %s" % (k, v))

			# Return the entire response object.
			return resp

		except urllib2.URLError, e:
			raise

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
