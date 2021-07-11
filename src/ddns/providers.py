#!/usr/bin/python3
###############################################################################
#                                                                             #
# ddns - A dynamic DNS client for IPFire                                      #
# Copyright (C) 2012-2017 IPFire development team                             #
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

import datetime
import logging
import os
import subprocess
import urllib.request
import urllib.error
import urllib.parse
import xml.dom.minidom

from .i18n import _

# Import all possible exception types.
from .errors import *

logger = logging.getLogger("ddns.providers")
logger.propagate = 1

_providers = {}

def get():
	"""
		Returns a dict with all automatically registered providers.
	"""
	return _providers.copy()

class DDNSProvider(object):
	# A short string that uniquely identifies
	# this provider.
	handle = None

	# The full name of the provider.
	name = None

	# A weburl to the homepage of the provider.
	# (Where to register a new account?)
	website = None

	# A list of supported protocols.
	protocols = ("ipv6", "ipv4")

	DEFAULT_SETTINGS = {}

	# holdoff time - Number of days no update is performed unless
	# the IP address has changed.
	holdoff_days = 30

	# holdoff time for update failures - Number of days no update
	# is tried after the last one has failed.
	holdoff_failure_days = 0.5

	# True if the provider is able to remove records, too.
	# Required to remove AAAA records if IPv6 is absent again.
	can_remove_records = True

	# True if the provider supports authentication via a random
	# generated token instead of username and password.
	supports_token_auth = True

	@staticmethod
	def supported():
		"""
			Should be overwritten to check if the system the code is running
			on has all the required tools to support this provider.
		"""
		return True

	def __init__(self, core, **settings):
		self.core = core

		# Copy a set of default settings and
		# update them by those from the configuration file.
		self.settings = self.DEFAULT_SETTINGS.copy()
		self.settings.update(settings)

	def __init_subclass__(cls, **kwargs):
		super().__init_subclass__(**kwargs)

		if not all((cls.handle, cls.name, cls.website)):
			raise DDNSError(_("Provider is not properly configured"))

		assert cls.handle not in _providers, \
			"Provider '%s' has already been registered" % cls.handle

		# Register class
		_providers[cls.handle] = cls

	def __repr__(self):
		return "<DDNS Provider %s (%s)>" % (self.name, self.handle)

	def __cmp__(self, other):
		return (lambda a, b: (a > b)-(a < b))(self.hostname, other.hostname)

	@property
	def db(self):
		return self.core.db

	def get(self, key, default=None):
		"""
			Get a setting from the settings dictionary.
		"""
		return self.settings.get(key, default)

	@property
	def hostname(self):
		"""
			Fast access to the hostname.
		"""
		return self.get("hostname")

	@property
	def username(self):
		"""
			Fast access to the username.
		"""
		return self.get("username")

	@property
	def password(self):
		"""
			Fast access to the password.
		"""
		return self.get("password")

	@property
	def token(self):
		"""
			Fast access to the token.
		"""
		return self.get("token")

	def __call__(self, force=False):
		if force:
			logger.debug(_("Updating %s forced") % self.hostname)

		# Do nothing if the last update has failed or no update is required
		elif self.has_failure or not self.requires_update:
			return

		# Execute the update.
		try:
			self.update()

		# 1) Catch network errors early, because we do not want to log
		# them to the database. They are usually temporary and caused
		# by the client side, so that we will retry quickly.
		# 2) If there is an internet server error (HTTP code 500) on the
		# provider's site, we will not log a failure and try again
		# shortly.
		except (DDNSNetworkError, DDNSInternalServerError):
			raise

		# In case of any errors, log the failed request and
		# raise the exception.
		except DDNSError as e:
			self.core.db.log_failure(self.hostname, e)
			raise

		logger.info(_("Dynamic DNS update for %(hostname)s (%(provider)s) successful") %
					{"hostname": self.hostname, "provider": self.name})
		self.core.db.log_success(self.hostname)

	def update(self):
		for protocol in self.protocols:
			if self.have_address(protocol):
				self.update_protocol(protocol)
			elif self.can_remove_records:
				self.remove_protocol(protocol)

	def update_protocol(self, proto):
		raise NotImplementedError

	def remove_protocol(self, proto):
		if not self.can_remove_records:
			raise RuntimeError("can_remove_records is enabled, but remove_protocol() not implemented")

		raise NotImplementedError

	@property
	def requires_update(self):
		# If the IP addresses have changed, an update is required
		if self.ip_address_changed(self.protocols):
			logger.debug(_("An update for %(hostname)s (%(provider)s) is performed because of an IP address change") %
			{"hostname": self.hostname, "provider": self.name})

			return True

		# If the holdoff time has expired, an update is required, too
		if self.holdoff_time_expired():
			logger.debug(_("An update for %(hostname)s (%(provider)s) is performed because the holdoff time has expired") %
						 {"hostname": self.hostname, "provider": self.name})

			return True

		# Otherwise, we don't need to perform an update
		logger.debug(_("No update required for %(hostname)s (%(provider)s)") %
					 {"hostname": self.hostname, "provider": self.name})

		return False

	@property
	def has_failure(self):
		"""
			Returns True when the last update has failed and no retry
			should be performed, yet.
		"""
		last_status = self.db.last_update_status(self.hostname)

		# Return False if the last update has not failed.
		if not last_status == "failure":
			return False

		# If there is no holdoff time, we won't update ever again.
		if self.holdoff_failure_days is None:
			logger.warning(_("An update has not been performed because earlier updates failed for %s") % self.hostname)
			logger.warning(_("There will be no retries"))

			return True

		# Determine when the holdoff time ends
		last_update = self.db.last_update(self.hostname, status=last_status)
		holdoff_end = last_update + datetime.timedelta(days=self.holdoff_failure_days)

		now = datetime.datetime.utcnow()
		if now < holdoff_end:
			failure_message = self.db.last_update_failure_message(self.hostname)

			logger.warning(_("An update has not been performed because earlier updates failed for %s") % self.hostname)

			if failure_message:
				logger.warning(_("Last failure message:"))

				for line in failure_message.splitlines():
					logger.warning("  %s" % line)

			logger.warning(_("Further updates will be withheld until %s") % holdoff_end)

			return True

		return False

	def ip_address_changed(self, protos):
		"""
			Returns True if this host is already up to date
			and does not need to change the IP address on the
			name server.
		"""
		for proto in protos:
			addresses = self.core.system.resolve(self.hostname, proto)
			current_address = self.get_address(proto)

			# Handle if the system has not got any IP address from a protocol
			# (i.e. had full dual-stack connectivity which it has not any more)
			if current_address is None:
				# If addresses still exists in the DNS system and if this provider
				# is able to remove records, we will do that.
				if addresses and self.can_remove_records:
					return True

				# Otherwise, we cannot go on...
				continue

			if not current_address in addresses:
				return True

		return False

	def holdoff_time_expired(self):
		"""
			Returns true if the holdoff time has expired
			and the host requires an update
		"""
		# If no holdoff days is defined, we cannot go on
		if not self.holdoff_days:
			return False

		# Get the timestamp of the last successfull update
		last_update = self.db.last_update(self.hostname, status="success")

		# If no timestamp has been recorded, no update has been
		# performed. An update should be performed now.
		if not last_update:
			return True

		# Determine when the holdoff time ends
		holdoff_end = last_update + datetime.timedelta(days=self.holdoff_days)

		now = datetime.datetime.utcnow()

		if now >= holdoff_end:
			logger.debug("The holdoff time has expired for %s" % self.hostname)
			return True
		else:
			logger.debug("Updates for %s are held off until %s" %
						 (self.hostname, holdoff_end))
			return False

	def send_request(self, *args, **kwargs):
		"""
			Proxy connection to the send request
			method.
		"""
		return self.core.system.send_request(*args, **kwargs)

	def get_address(self, proto, default=None):
		"""
			Proxy method to get the current IP address.
		"""
		return self.core.system.get_address(proto) or default

	def have_address(self, proto):
		"""
			Returns True if an IP address for the given protocol
			is known and usable.
		"""
		address = self.get_address(proto)

		if address:
			return True

		return False


class DDNSProtocolDynDNS2(object):
	"""
		This is an abstract class that implements the DynDNS updater
		protocol version 2. As this is a popular way to update dynamic
		DNS records, this class is supposed make the provider classes
		shorter and simpler.
	"""

	# Information about the format of the request is to be found
	# http://dyn.com/support/developers/api/perform-update/
	# http://dyn.com/support/developers/api/return-codes/

	# The DynDNS protocol version 2 does not allow to remove records
	can_remove_records = False

	# The DynDNS protocol version 2 only supports authentication via
	# username and password.
	supports_token_auth = False

	def prepare_request_data(self, proto):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(proto),
		}

		return data

	def update_protocol(self, proto):
		data = self.prepare_request_data(proto)

		return self.send_request(data)

	def send_request(self, data):
		# Send update to the server.
		response = DDNSProvider.send_request(self, self.url, data=data, username=self.username, password=self.password)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("good") or output.startswith("nochg"):
			return

		# Handle error codes.
		if output == "badauth":
			raise DDNSAuthenticationError
		elif output == "abuse":
			raise DDNSAbuseError
		elif output == "notfqdn":
			raise DDNSRequestError(_("No valid FQDN was given"))
		elif output == "nohost":
			raise DDNSRequestError(_("Specified host does not exist"))
		elif output == "911":
			raise DDNSInternalServerError
		elif output == "dnserr":
			raise DDNSInternalServerError(_("DNS error encountered"))
		elif output == "badagent":
			raise DDNSBlockedError
		elif output == "badip":
			raise DDNSBlockedError

		# If we got here, some other update error happened.
		raise DDNSUpdateError(_("Server response: %s") % output)


class DDNSResponseParserXML(object):
	"""
		This class provides a parser for XML responses which
		will be sent by various providers. This class uses the python
		shipped XML minidom module to walk through the XML tree and return
		a requested element.
	"""

	def get_xml_tag_value(self, document, content):
		# Send input to the parser.
		xmldoc = xml.dom.minidom.parseString(document)

		# Get XML elements by the given content.
		element = xmldoc.getElementsByTagName(content)

		# If no element has been found, we directly can return None.
		if not element:
			return None

		# Only get the first child from an element, even there are more than one.
		firstchild = element[0].firstChild

		# Get the value of the child.
		value = firstchild.nodeValue

		# Return the value.
		return value


class DDNSProviderAllInkl(DDNSProvider):
	handle    = "all-inkl.com"
	name      = "All-inkl.com"
	website   = "http://all-inkl.com/"
	protocols = ("ipv4",)

	# There are only information provided by the vendor how to
	# perform an update on a FRITZ Box. Grab requried informations
	# from the net.
	# http://all-inkl.goetze.it/v01/ddns-mit-einfachen-mitteln/

	url = "http://dyndns.kasserver.com"
	can_remove_records = False
	supports_token_auth = False

	def update(self):
		# There is no additional data required so we directly can
		# send our request.
		response = self.send_request(self.url, username=self.username, password=self.password)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("good") or output.startswith("nochg"):
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderBindNsupdate(DDNSProvider):
	handle  = "nsupdate"
	name    = "BIND nsupdate utility"
	website = "http://en.wikipedia.org/wiki/Nsupdate"

	DEFAULT_TTL = 60

	supports_token_auth = False

	@staticmethod
	def supported():
		# Search if the nsupdate utility is available
		paths = os.environ.get("PATH")

		for path in paths.split(":"):
			executable = os.path.join(path, "nsupdate")

			if os.path.exists(executable):
				return True

		return False

	def update(self):
		scriptlet = self.__make_scriptlet()

		# -v enables TCP hence we transfer keys and other data that may
		# exceed the size of one packet.
		# -t sets the timeout
		command = ["nsupdate", "-v", "-t", "60"]

		p = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = p.communicate(scriptlet)

		if p.returncode == 0:
			return

		raise DDNSError("nsupdate terminated with error code: %s\n  %s" % (p.returncode, stderr))

	def __make_scriptlet(self):
		scriptlet = []

		# Set a different server the update is sent to.
		server = self.get("server", None)
		if server:
			scriptlet.append("server %s" % server)

		# Set the DNS zone the host should be added to.
		zone = self.get("zone", None)
		if zone:
			scriptlet.append("zone %s" % zone)

		key = self.get("key", None)
		if key:
			secret = self.get("secret")

			scriptlet.append("key %s %s" % (key, secret))

		ttl = self.get("ttl", self.DEFAULT_TTL)

		# Perform an update for each supported protocol.
		for rrtype, proto in (("AAAA", "ipv6"), ("A", "ipv4")):
			address = self.get_address(proto)
			if not address:
				continue

			scriptlet.append("update delete %s. %s" % (self.hostname, rrtype))
			scriptlet.append("update add %s. %s %s %s" % \
				(self.hostname, ttl, rrtype, address))

		# Send the actions to the server.
		scriptlet.append("send")
		scriptlet.append("quit")

		logger.debug(_("Scriptlet:"))
		for line in scriptlet:
			# Masquerade the line with the secret key.
			if line.startswith("key"):
				line = "key **** ****"

			logger.debug("  %s" % line)

		return "\n".join(scriptlet).encode()


class DDNSProviderChangeIP(DDNSProvider):
	handle    = "changeip.com"
	name      = "ChangeIP.com"
	website   = "https://changeip.com"
	protocols = ("ipv4",)

	# Detailed information about the update api can be found here.
	# http://www.changeip.com/accounts/knowledgebase.php?action=displayarticle&id=34

	url = "https://nic.changeip.com/nic/update"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(proto),
		}

		# Send update to the server.
		try:
			response = self.send_request(self.url, username=self.username, password=self.password, data=data)

		# Handle error codes.
		except urllib.error.HTTPError as e:
			if e.code == 422:
				raise DDNSRequestError(_("Domain not found."))

			raise

		# Handle success message.
		if response.code == 200:
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError(_("Server response: %s") % output)


class DDNSProviderDesecIO(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "desec.io"
	name      = "desec.io"
	website   = "https://www.desec.io"
	protocols = ("ipv6", "ipv4",)

	# ipv4 / ipv6 records are automatically removed when the update
	# request originates from the respectively other protocol and no
	# address is explicitly provided for the unused protocol.

	url = "https://update.dedyn.io"

	# desec.io sends the IPv6 and IPv4 address in one request

	def update(self):
		data = DDNSProtocolDynDNS2.prepare_request_data(self, "ipv4")

		# This one supports IPv6
		myipv6 = self.get_address("ipv6")

		# Add update information if we have an IPv6 address.
		if myipv6:
			data["myipv6"] = myipv6

		self.send_request(data)


class DDNSProviderDDNSS(DDNSProvider):
	handle    = "ddnss.de"
	name      = "DDNSS"
	website   = "http://www.ddnss.de"
	protocols = ("ipv4",)

	# Detailed information about how to send the update request and possible response
	# codes can be obtained from here.
	# http://www.ddnss.de/info.php
	# http://www.megacomputing.de/2014/08/dyndns-service-response-time/#more-919

	url = "http://www.ddnss.de/upd.php"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"ip"   : self.get_address(proto),
			"host" : self.hostname,
		}

		# Check if a token has been set.
		if self.token:
			data["key"] = self.token

		# Check if username and hostname are given.
		elif self.username and self.password:
			data.update({
				"user" : self.username,
				"pwd"  : self.password,
			})

		# Raise an error if no auth details are given.
		else:
			raise DDNSConfigurationError

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# This provider sends the response code as part of the header.
		# Get status information from the header.
		output = response.getheader('ddnss-response')

		# Handle success messages.
		if output == "good" or output == "nochg":
			return

		# Handle error codes.
		if output == "badauth":
			raise DDNSAuthenticationError
		elif output == "notfqdn":
			raise DDNSRequestError(_("No valid FQDN was given"))
		elif output == "nohost":
			raise DDNSRequestError(_("Specified host does not exist"))
		elif output == "911":
			raise DDNSInternalServerError
		elif output == "dnserr":
			raise DDNSInternalServerError(_("DNS error encountered"))
		elif output == "disabled":
			raise DDNSRequestError(_("Account disabled or locked"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDHS(DDNSProvider):
	handle    = "dhs.org"
	name      = "DHS International"
	website   = "http://dhs.org/"
	protocols = ("ipv4",)

	# No information about the used update api provided on webpage,
	# grabed from source code of ez-ipudate.

	url = "http://members.dhs.org/nic/hosts"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"domain"       : self.hostname,
			"ip"           : self.get_address(proto),
			"hostcmd"      : "edit",
			"hostcmdstage" : "2",
			"type"         : "4",
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password, data=data)

		# Handle success messages.
		if response.code == 200:
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDNSpark(DDNSProvider):
	handle    = "dnspark.com"
	name      = "DNS Park"
	website   = "http://dnspark.com/"
	protocols = ("ipv4",)

	# Informations to the used api can be found here:
	# https://dnspark.zendesk.com/entries/31229348-Dynamic-DNS-API-Documentation

	url = "https://control.dnspark.com/api/dynamic/update.php"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"domain" : self.hostname,
			"ip"     : self.get_address(proto),
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("ok") or output.startswith("nochange"):
			return

		# Handle error codes.
		if output == "unauth":
			raise DDNSAuthenticationError
		elif output == "abuse":
			raise DDNSAbuseError
		elif output == "blocked":
			raise DDNSBlockedError
		elif output == "nofqdn":
			raise DDNSRequestError(_("No valid FQDN was given"))
		elif output == "nohost":
			raise DDNSRequestError(_("Invalid hostname specified"))
		elif output == "notdyn":
			raise DDNSRequestError(_("Hostname not marked as a dynamic host"))
		elif output == "invalid":
			raise DDNSRequestError(_("Invalid IP address has been sent"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDtDNS(DDNSProvider):
	handle    = "dtdns.com"
	name      = "DtDNS"
	website   = "http://dtdns.com/"
	protocols = ("ipv4",)

	# Information about the format of the HTTPS request is to be found
	# http://www.dtdns.com/dtsite/updatespec

	url = "https://www.dtdns.com/api/autodns.cfm"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"ip" : self.get_address(proto),
			"id" : self.hostname,
			"pw" : self.password
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Remove all leading and trailing whitespace.
		output = output.strip()

		# Handle success messages.
		if "now points to" in output:
			return

		# Handle error codes.
		if output == "No hostname to update was supplied.":
			raise DDNSRequestError(_("No hostname specified"))

		elif output == "The hostname you supplied is not valid.":
			raise DDNSRequestError(_("Invalid hostname specified"))

		elif output == "The password you supplied is not valid.":
			raise DDNSAuthenticationError

		elif output == "Administration has disabled this account.":
			raise DDNSRequestError(_("Account has been disabled"))

		elif output == "Illegal character in IP.":
			raise DDNSRequestError(_("Invalid IP address has been sent"))

		elif output == "Too many failed requests.":
			raise DDNSRequestError(_("Too many failed requests"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDuckDNS(DDNSProvider):
	handle    = "duckdns.org"
	name      = "Duck DNS"
	website   = "http://www.duckdns.org/"
	protocols = ("ipv6", "ipv4",)

	# Information about the format of the request is to be found
	# https://www.duckdns.org/spec.jsp

	url = "https://www.duckdns.org/update"
	can_remove_records = False
	supports_token_auth = True

	def update(self):
		# Raise an error if no auth details are given.
		if not self.token:
			raise DDNSConfigurationError

		data =  {
			"domains" : self.hostname,
			"token"    : self.token,
		}

		# Check if we update an IPv4 address.
		address4 = self.get_address("ipv4")
		if address4:
			data["ip"] = address4

		# Check if we update an IPv6 address.
		address6 = self.get_address("ipv6")
		if address6:
			data["ipv6"] = address6

		# Raise an error if no address is given.
		if "ip" not in data and "ipv6" not in data:
			raise DDNSConfigurationError

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Remove all leading and trailing whitespace.
		output = output.strip()

		# Handle success messages.
		if output == "OK":
			return

		# The provider does not give detailed information
		# if the update fails. Only a "KO" will be sent back.
		if output == "KO":
			raise DDNSUpdateError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDyFi(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "dy.fi"
	name      = "dy.fi"
	website   = "https://www.dy.fi/"
	protocols = ("ipv4",)

	# Information about the format of the request is to be found
	# https://www.dy.fi/page/clients?lang=en
	# https://www.dy.fi/page/specification?lang=en

	url = "https://www.dy.fi/nic/update"

	# Please only send automatic updates when your IP address changes,
	# or once per 5 to 6 days to refresh the address mapping (they will
	# expire if not refreshed within 7 days).
	holdoff_days = 6


class DDNSProviderDynDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "dyndns.org"
	name      = "Dyn"
	website   = "http://dyn.com/dns/"
	protocols = ("ipv4",)

	# Information about the format of the request is to be found
	# http://http://dyn.com/support/developers/api/perform-update/
	# http://dyn.com/support/developers/api/return-codes/

	url = "https://members.dyndns.org/nic/update"


class DDNSProviderDomainOffensive(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "do.de"
	name      = "Domain-Offensive"
	website   = "https://www.do.de/"
	protocols = ("ipv6", "ipv4")

	# Detailed information about the request and response codes
	# are available on the providers webpage.
	# https://www.do.de/wiki/FlexDNS_-_Entwickler

	url = "https://ddns.do.de/"

class DDNSProviderDynUp(DDNSProvider):
	handle    = "dynup.de"
	name      = "DynUp.DE"
	website   = "http://dynup.de/"
	protocols = ("ipv4",)

	# Information about the format of the HTTPS request is to be found
	# https://dyndnsfree.de/user/hilfe.php

	url = "https://dynup.de/dyn.php"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"username" : self.username,
			"password" : self.password,
			"hostname" : self.hostname,
			"print" : '1',
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Remove all leading and trailing whitespace.
		output = output.strip()

		# Handle success messages.
		if output.startswith("I:OK"):
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDynU(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "dynu.com"
	name      = "Dynu"
	website   = "http://dynu.com/"
	protocols = ("ipv6", "ipv4",)

	# Detailed information about the request and response codes
	# are available on the providers webpage.
	# http://dynu.com/Default.aspx?page=dnsapi

	url = "https://api.dynu.com/nic/update"

	# DynU sends the IPv6 and IPv4 address in one request

	def update(self):
		data = DDNSProtocolDynDNS2.prepare_request_data(self, "ipv4")

		# This one supports IPv6
		myipv6 = self.get_address("ipv6")

		# Add update information if we have an IPv6 address.
		if myipv6:
			data["myipv6"] = myipv6

		self.send_request(data)


class DDNSProviderEasyDNS(DDNSProvider):
	handle    = "easydns.com"
	name      = "EasyDNS"
	website   = "http://www.easydns.com/"
	protocols = ("ipv4",)

	# Detailed information about the request and response codes
	# (API 1.3) are available on the providers webpage.
	# https://fusion.easydns.com/index.php?/Knowledgebase/Article/View/102/7/dynamic-dns

	url = "http://api.cp.easydns.com/dyn/tomato.php"

	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"myip"     : self.get_address(proto, "-"),
			"hostname" : self.hostname,
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data, username=self.username, password=self.password)

		# Get the full response message.
		output = response.read().decode()

		# Remove all leading and trailing whitespace.
		output = output.strip()

		# Handle success messages.
		if output.startswith("NOERROR"):
			return

		# Handle error codes.
		if output.startswith("NOACCESS"):
			raise DDNSAuthenticationError

		elif output.startswith("NOSERVICE"):
			raise DDNSRequestError(_("Dynamic DNS is not turned on for this domain"))

		elif output.startswith("ILLEGAL INPUT"):
			raise DDNSRequestError(_("Invalid data has been sent"))

		elif output.startswith("TOOSOON"):
			raise DDNSRequestError(_("Too frequent update requests have been sent"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDomopoli(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "domopoli.de"
	name      = "domopoli.de"
	website   = "http://domopoli.de/"
	protocols = ("ipv4",)

	# https://www.domopoli.de/?page=howto#DynDns_start

	url = "http://dyndns.domopoli.de/nic/update"


class DDNSProviderDynsNet(DDNSProvider):
	handle    = "dyns.net"
	name      = "DyNS"
	website   = "http://www.dyns.net/"
	protocols = ("ipv4",)
	can_remove_records = False
	supports_token_auth = False

	# There is very detailed informatio about how to send the update request and
	# the possible response codes. (Currently we are using the v1.1 proto)
	# http://www.dyns.net/documentation/technical/protocol/

	url = "http://www.dyns.net/postscript011.php"

	def update_protocol(self, proto):
		data = {
			"ip"       : self.get_address(proto),
			"host"     : self.hostname,
			"username" : self.username,
			"password" : self.password,
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("200"):
			return

		# Handle error codes.
		if output.startswith("400"):
			raise DDNSRequestError(_("Malformed request has been sent"))
		elif output.startswith("401"):
			raise DDNSAuthenticationError
		elif output.startswith("402"):
			raise DDNSRequestError(_("Too frequent update requests have been sent"))
		elif output.startswith("403"):
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError(_("Server response: %s") % output)


class DDNSProviderEnomCom(DDNSResponseParserXML, DDNSProvider):
	handle    = "enom.com"
	name      = "eNom Inc."
	website   = "http://www.enom.com/"
	protocols = ("ipv4",)

	# There are very detailed information about how to send an update request and
	# the respone codes.
	# http://www.enom.com/APICommandCatalog/

	url = "https://dynamic.name-services.com/interface.asp"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"command"        : "setdnshost",
			"responsetype"   : "xml",
			"address"        : self.get_address(proto),
			"domainpassword" : self.password,
			"zone"           : self.hostname
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if self.get_xml_tag_value(output, "ErrCount") == "0":
			return

		# Handle error codes.
		errorcode = self.get_xml_tag_value(output, "ResponseNumber")

		if errorcode == "304155":
			raise DDNSAuthenticationError
		elif errorcode == "304153":
			raise DDNSRequestError(_("Domain not found"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderEntryDNS(DDNSProvider):
	handle    = "entrydns.net"
	name      = "EntryDNS"
	website   = "http://entrydns.net/"
	protocols = ("ipv4",)

	# Some very tiny details about their so called "Simple API" can be found
	# here: https://entrydns.net/help
	url = "https://entrydns.net/records/modify"
	can_remove_records = False
	supports_token_auth = True

	def update_protocol(self, proto):
		data = {
			"ip" : self.get_address(proto),
		}

		# Add auth token to the update url.
		url = "%s/%s" % (self.url, self.token)

		# Send update to the server.
		try:
			response = self.send_request(url, data=data)

		# Handle error codes
		except urllib.error.HTTPError as e:
			if e.code == 404:
				raise DDNSAuthenticationError

			elif e.code == 422:
				raise DDNSRequestError(_("An invalid IP address was submitted"))

			raise

		# Handle success messages.
		if response.code == 200:
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderFreeDNSAfraidOrg(DDNSProvider):
	handle    = "freedns.afraid.org"
	name      = "freedns.afraid.org"
	website   = "http://freedns.afraid.org/"

	# No information about the request or response could be found on the vendor
	# page. All used values have been collected by testing.
	url = "https://freedns.afraid.org/dynamic/update.php"
	can_remove_records = False
	supports_token_auth = True

	def update_protocol(self, proto):
		data = {
			"address" : self.get_address(proto),
		}

		# Add auth token to the update url.
		url = "%s?%s" % (self.url, self.token)

		# Send update to the server.
		response = self.send_request(url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("Updated") or "has not changed" in output:
			return

		# Handle error codes.
		if output == "ERROR: Unable to locate this record":
			raise DDNSAuthenticationError
		elif "is an invalid IP address" in output:
			raise DDNSRequestError(_("Invalid IP address has been sent"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderHENet(DDNSProtocolDynDNS2, DDNSProvider):
                handle    = "he.net"
                name      = "he.net"
                website   = "https://he.net"
                protocols = ("ipv6", "ipv4",)

                # Detailed information about the update api can be found here.
                # http://dns.he.net/docs.html

                url = "https://dyn.dns.he.net/nic/update"
                @property
                def username(self):
                        return self.get("hostname")

		

class DDNSProviderItsdns(DDNSProtocolDynDNS2, DDNSProvider):
		handle    = "inwx.com"
		name      = "INWX"
		website   = "https://www.inwx.com"
		protocols = ("ipv6", "ipv4")

		# Information about the format of the HTTP request is to be found
		# here: https://www.inwx.com/en/nameserver2/dyndns (requires login)
		# Notice: The URL is the same for: inwx.com|de|at|ch|es

		url = "https://dyndns.inwx.com/nic/update"


class DDNSProviderItsdns(DDNSProtocolDynDNS2, DDNSProvider):
		handle    = "itsdns.de"
		name      = "it's DNS"
		website   = "http://www.itsdns.de/"
		protocols = ("ipv6", "ipv4")

		# Information about the format of the HTTP request is to be found
		# here: https://www.itsdns.de/dynupdatehelp.htm

		url = "https://www.itsdns.de/update.php"


class DDNSProviderJoker(DDNSProtocolDynDNS2, DDNSProvider):
		handle  = "joker.com"
		name    = "Joker.com Dynamic DNS"
		website = "https://joker.com/"
		protocols = ("ipv4",)

		# Information about the request can be found here:
		# https://joker.com/faq/content/11/427/en/what-is-dynamic-dns-dyndns.html
		# Using DynDNS V2 protocol over HTTPS here

		url = "https://svc.joker.com/nic/update"


class DDNSProviderKEYSYSTEMS(DDNSProvider):
	handle    = "key-systems.net"
	name      = "dynamicdns.key-systems.net"
	website   = "https://domaindiscount24.com/"
	protocols = ("ipv4",)

	# There are only information provided by the domaindiscount24 how to
	# perform an update with HTTP APIs
	# https://www.domaindiscount24.com/faq/dynamic-dns
	# examples: https://dynamicdns.key-systems.net/update.php?hostname=hostname&password=password&ip=auto
	#           https://dynamicdns.key-systems.net/update.php?hostname=hostname&password=password&ip=213.x.x.x&mx=213.x.x.x

	url = "https://dynamicdns.key-systems.net/update.php"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		address = self.get_address(proto)
		data = {
			"hostname"      : self.hostname,
			"password"      : self.password,
			"ip"            : address,
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if "code = 200" in output:
			return

		# Handle error messages.
		if "abuse prevention triggered" in output:
			raise DDNSAbuseError
		elif "invalid password" in output:
			raise DDNSAuthenticationError
		elif "Authorization failed" in output:
			raise DDNSRequestError(_("Invalid hostname specified"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderGoogle(DDNSProtocolDynDNS2, DDNSProvider):
        handle    = "domains.google.com"
        name      = "Google Domains"
        website   = "https://domains.google.com/"
        protocols = ("ipv4",)

        # Information about the format of the HTTP request is to be found
        # here: https://support.google.com/domains/answer/6147083?hl=en

        url = "https://domains.google.com/nic/update"


class DDNSProviderLightningWireLabs(DDNSProvider):
	handle    = "dns.lightningwirelabs.com"
	name      = "Lightning Wire Labs DNS Service"
	website   = "https://dns.lightningwirelabs.com/"

	# Information about the format of the HTTPS request is to be found
	# https://dns.lightningwirelabs.com/knowledge-base/api/ddns

	supports_token_auth = True

	url = "https://dns.lightningwirelabs.com/update"

	def update(self):
		# Raise an error if no auth details are given.
		if not self.token:
			raise DDNSConfigurationError

		data =  {
			"hostname" : self.hostname,
			"token"    : self.token,
			"address6" : self.get_address("ipv6", "-"),
			"address4" : self.get_address("ipv4", "-"),
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Handle success messages.
		if response.code == 200:
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderLoopia(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "loopia.se"
	name      = "Loopia AB"
	website   = "https://www.loopia.com"
	protocols = ("ipv4",)

	# Information about the format of the HTTP request is to be found
	# here: https://support.loopia.com/wiki/About_the_DynDNS_support

	url = "https://dns.loopia.se/XDynDNSServer/XDynDNS.php"


class DDNSProviderMyOnlinePortal(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "myonlineportal.net"
	name      = "myonlineportal.net"
	website   = "https:/myonlineportal.net/"

	# Information about the request and response can be obtained here:
	# https://myonlineportal.net/howto_dyndns

	url = "https://myonlineportal.net/updateddns"

	def prepare_request_data(self, proto):
		data = {
			"hostname" : self.hostname,
			"ip"     : self.get_address(proto),
		}

		return data


class DDNSProviderNamecheap(DDNSResponseParserXML, DDNSProvider):
	handle    = "namecheap.com"
	name      = "Namecheap"
	website   = "http://namecheap.com"
	protocols = ("ipv4",)

	# Information about the format of the HTTP request is to be found
	# https://www.namecheap.com/support/knowledgebase/article.aspx/9249/0/nc-dynamic-dns-to-dyndns-adapter
	# https://community.namecheap.com/forums/viewtopic.php?f=6&t=6772

	url = "https://dynamicdns.park-your-domain.com/update"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		# Namecheap requires the hostname splitted into a host and domain part.
		host, domain = self.hostname.split(".", 1)

		# Get and store curent IP address.
		address = self.get_address(proto)

		data = {
			"ip"       : address,
			"password" : self.password,
			"host"     : host,
			"domain"   : domain
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if self.get_xml_tag_value(output, "IP") == address:
			return

		# Handle error codes.
		errorcode = self.get_xml_tag_value(output, "ResponseNumber")

		if errorcode == "304156":
			raise DDNSAuthenticationError
		elif errorcode == "316153":
			raise DDNSRequestError(_("Domain not found"))
		elif errorcode == "316154":
			raise DDNSRequestError(_("Domain not active"))
		elif errorcode in ("380098", "380099"):
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderNOIP(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "no-ip.com"
	name      = "NoIP"
	website   = "http://www.noip.com/"
	protocols = ("ipv4",)

	# Information about the format of the HTTP request is to be found
	# here: http://www.noip.com/integrate/request and
	# here: http://www.noip.com/integrate/response

	url = "https://dynupdate.noip.com/nic/update"

	def prepare_request_data(self, proto):
		assert proto == "ipv4"

		data = {
			"hostname" : self.hostname,
			"address"  : self.get_address(proto),
		}

		return data


class DDNSProviderNowDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "now-dns.com"
	name      = "NOW-DNS"
	website   = "http://now-dns.com/"
	protocols = ("ipv6", "ipv4")

	# Information about the format of the request is to be found
	# but only can be accessed by register an account and login
	# https://now-dns.com/?m=api

	url = "https://now-dns.com/update"


class DDNSProviderNsupdateINFO(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "nsupdate.info"
	name      = "nsupdate.info"
	website   = "http://nsupdate.info/"
	protocols = ("ipv6", "ipv4",)

	# Information about the format of the HTTP request can be found
	# after login on the provider user interface and here:
	# http://nsupdateinfo.readthedocs.org/en/latest/user.html

	url = "https://nsupdate.info/nic/update"

	# TODO nsupdate.info can actually do this, but the functionality
	# has not been implemented here, yet.
	can_remove_records = False

	supports_token_auth = True

	# After a failed update, there will be no retries
	# https://bugzilla.ipfire.org/show_bug.cgi?id=10603
	holdoff_failure_days = None

	# Nsupdate.info uses the hostname as user part for the HTTP basic auth,
	# and for the password a so called secret.
	@property
	def username(self):
		return self.get("hostname")

	@property
	def password(self):
		return self.token or self.get("secret")

	def prepare_request_data(self, proto):
		data = {
			"myip" : self.get_address(proto),
		}

		return data


class DDNSProviderOpenDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "opendns.com"
	name      = "OpenDNS"
	website   = "http://www.opendns.com"

	# Detailed information about the update request and possible
	# response codes can be obtained from here:
	# https://support.opendns.com/entries/23891440

	url = "https://updates.opendns.com/nic/update"

	def prepare_request_data(self, proto):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(proto),
		}

		return data


class DDNSProviderOVH(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "ovh.com"
	name      = "OVH"
	website   = "http://www.ovh.com/"
	protocols = ("ipv4",)

	# OVH only provides very limited information about how to
	# update a DynDNS host. They only provide the update url
	# on the their german subpage.
	#
	# http://hilfe.ovh.de/DomainDynHost

	url = "https://www.ovh.com/nic/update"

	def prepare_request_data(self, proto):
		data = DDNSProtocolDynDNS2.prepare_request_data(self, proto)
		data.update({
			"system" : "dyndns",
		})

		return data


class DDNSProviderRegfish(DDNSProvider):
	handle  = "regfish.com"
	name    = "Regfish GmbH"
	website = "http://www.regfish.com/"

	# A full documentation to the providers api can be found here
	# but is only available in german.
	# https://www.regfish.de/domains/dyndns/dokumentation

	url = "https://dyndns.regfish.de/"
	can_remove_records = False
	supports_token_auth = True

	def update(self):
		data = {
			"fqdn" : self.hostname,
		}

		# Check if we update an IPv6 address.
		address6 = self.get_address("ipv6")
		if address6:
			data["ipv6"] = address6

		# Check if we update an IPv4 address.
		address4 = self.get_address("ipv4")
		if address4:
			data["ipv4"] = address4

		# Raise an error if none address is given.
		if "ipv6" not in data and "ipv4" not in data:
			raise DDNSConfigurationError

		# Check if a token has been set.
		if self.token:
			data["token"] = self.token

		# Raise an error if no token and no useranem and password
		# are given.
		elif not self.username and not self.password:
			raise DDNSConfigurationError(_("No Auth details specified"))

		# HTTP Basic Auth is only allowed if no token is used.
		if self.token:
			# Send update to the server.
			response = self.send_request(self.url, data=data)
		else:
			# Send update to the server.
			response = self.send_request(self.url, username=self.username, password=self.password, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if "100" in output or "101" in output:
			return

		# Handle error codes.
		if "401" or "402" in output:
			raise DDNSAuthenticationError
		elif "408" in output:
			raise DDNSRequestError(_("Invalid IPv4 address has been sent"))
		elif "409" in output:
			raise DDNSRequestError(_("Invalid IPv6 address has been sent"))
		elif "412" in output:
			raise DDNSRequestError(_("No valid FQDN was given"))
		elif "414" in output:
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderSchokokeksDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "schokokeks.org"
	name      = "Schokokeks"
	website   = "http://www.schokokeks.org/"
	protocols = ("ipv4",)

	# Information about the format of the request is to be found
	# https://wiki.schokokeks.org/DynDNS
	url = "https://dyndns.schokokeks.org/nic/update"


class DDNSProviderSelfhost(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "selfhost.de"
	name      = "Selfhost.de"
	website   = "http://www.selfhost.de/"
	protocols = ("ipv4",)

	url = "https://carol.selfhost.de/nic/update"

	def prepare_request_data(self, proto):
		data = DDNSProtocolDynDNS2.prepare_request_data(self, proto)
		data.update({
			"hostname" : "1",
		})

		return data


class DDNSProviderServercow(DDNSProvider):
	handle    = "servercow.de"
	name      = "servercow.de"
	website   = "https://servercow.de/"
	protocols = ("ipv4", "ipv6")

	url = "https://www.servercow.de/dnsupdate/update.php"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"ipaddr"   : self.get_address(proto),
			"hostname" : self.hostname,
			"username" : self.username,
			"pass"     : self.password,
		}

		# Send request to provider
		response = self.send_request(self.url, data=data)

		# Read response
		output = response.read().decode()

		# Server responds with OK if update was successful
		if output.startswith("OK"):
			return

		# Catch any errors
		elif output.startswith("FAILED - Authentication failed"):
			raise DDNSAuthenticationError

		# If we got here, some other update error happened
		raise DDNSUpdateError(output)


class DDNSProviderSPDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "spdns.org"
	name      = "SPDYN"
	website   = "https://www.spdyn.de/"

	# Detailed information about request and response codes are provided
	# by the vendor. They are using almost the same mechanism and status
	# codes as dyndns.org so we can inherit all those stuff.
	#
	# http://wiki.securepoint.de/index.php/SPDNS_FAQ
	# http://wiki.securepoint.de/index.php/SPDNS_Update-Tokens

	url = "https://update.spdyn.de/nic/update"

	supports_token_auth = True

	@property
	def username(self):
		return self.get("username") or self.hostname

	@property
	def password(self):
		return self.get("password") or self.token


class DDNSProviderStrato(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "strato.com"
	name      = "Strato AG"
	website   = "http:/www.strato.com/"
	protocols = ("ipv4",)

	# Information about the request and response can be obtained here:
	# http://www.strato-faq.de/article/671/So-einfach-richten-Sie-DynDNS-f%C3%BCr-Ihre-Domains-ein.html

	url = "https://dyndns.strato.com/nic/update"

	def prepare_request_data(self, proto):
		data = DDNSProtocolDynDNS2.prepare_request_data(self, proto)
		data.update({
			"mx" : "NOCHG",
			"backupmx" : "NOCHG"
		})

		return data


class DDNSProviderTwoDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "twodns.de"
	name      = "TwoDNS"
	website   = "http://www.twodns.de"
	protocols = ("ipv4",)

	# Detailed information about the request can be found here
	# http://twodns.de/en/faqs
	# http://twodns.de/en/api

	url = "https://update.twodns.de/update"

	def prepare_request_data(self, proto):
		assert proto == "ipv4"

		data = {
			"ip"       : self.get_address(proto),
			"hostname" : self.hostname
		}

		return data


class DDNSProviderUdmedia(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "udmedia.de"
	name      = "Udmedia GmbH"
	website   = "http://www.udmedia.de"
	protocols = ("ipv4",)

	# Information about the request can be found here
	# http://www.udmedia.de/faq/content/47/288/de/wie-lege-ich-einen-dyndns_eintrag-an.html

	url = "https://www.udmedia.de/nic/update"


class DDNSProviderVariomedia(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "variomedia.de"
	name      = "Variomedia"
	website   = "http://www.variomedia.de/"
	protocols = ("ipv6", "ipv4",)

	# Detailed information about the request can be found here
	# https://dyndns.variomedia.de/

	url = "https://dyndns.variomedia.de/nic/update"

	def prepare_request_data(self, proto):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(proto),
		}

		return data


class DDNSProviderXLhost(DDNSProtocolDynDNS2, DDNSProvider):
        handle    = "xlhost.de"
        name	  = "XLhost"
        website   = "http://xlhost.de/"
        protocols = ("ipv4",)

        # Information about the format of the HTTP request is to be found
        # here: https://xlhost.de/faq/index_html?topicId=CQA2ELIPO4SQ

        url = "https://nsupdate.xlhost.de/"


class DDNSProviderZoneedit(DDNSProvider):
	handle    = "zoneedit.com"
	name      = "Zoneedit"
	website   = "http://www.zoneedit.com"
	protocols = ("ipv4",)

	supports_token_auth = False

	# Detailed information about the request and the response codes can be
	# obtained here:
	# http://www.zoneedit.com/doc/api/other.html
	# http://www.zoneedit.com/faq.html

	url = "https://dynamic.zoneedit.com/auth/dynamic.html"

	def update_protocol(self, proto):
		data = {
			"dnsto" : self.get_address(proto),
			"host"  : self.hostname
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("<SUCCESS"):
			return

		# Handle error codes.
		if output.startswith("invalid login"):
			raise DDNSAuthenticationError
		elif output.startswith("<ERROR CODE=\"704\""):
			raise DDNSRequestError(_("No valid FQDN was given"))
		elif output.startswith("<ERROR CODE=\"702\""):
			raise DDNSRequestError(_("Too frequent update requests have been sent"))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDNSmadeEasy(DDNSProvider):
	handle    = "dnsmadeeasy.com"
	name      = "DNSmadeEasy.com"
	website   = "http://www.dnsmadeeasy.com/"
	protocols = ("ipv4",)

	# DNS Made Easy Nameserver Provider also offering Dynamic DNS
	# Documentation can be found here:
	# http://www.dnsmadeeasy.com/dynamic-dns/

	url = "https://cp.dnsmadeeasy.com/servlet/updateip?"
	can_remove_records = False
	supports_token_auth = False

	def update_protocol(self, proto):
		data = {
			"ip" : self.get_address(proto),
			"id" : self.hostname,
			"username" : self.username,
			"password" : self.password,
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read().decode()

		# Handle success messages.
		if output.startswith("success") or output.startswith("error-record-ip-same"):
			return

		# Handle error codes.
		if output.startswith("error-auth-suspend"):
			raise DDNSRequestError(_("Account has been suspended"))

		elif output.startswith("error-auth-voided"):
			raise DDNSRequestError(_("Account has been revoked"))

		elif output.startswith("error-record-invalid"):
			raise DDNSRequestError(_("Specified host does not exist"))

		elif output.startswith("error-auth"):
			raise DDNSAuthenticationError

		# If we got here, some other update error happened.
		raise DDNSUpdateError(_("Server response: %s") % output)


class DDNSProviderZZZZ(DDNSProvider):
	handle    = "zzzz.io"
	name      = "zzzz"
	website   = "https://zzzz.io"
	protocols = ("ipv6", "ipv4",)

	# Detailed information about the update request can be found here:
	# https://zzzz.io/faq/

	# Details about the possible response codes have been provided in the bugtracker:
	# https://bugzilla.ipfire.org/show_bug.cgi?id=10584#c2

	url = "https://zzzz.io/api/v1/update"
	can_remove_records = False
	supports_token_auth = True

	def update_protocol(self, proto):
		data = {
			"ip"    : self.get_address(proto),
			"token" : self.token,
		}

		if proto == "ipv6":
			data["type"] = "aaaa"

		# zzzz uses the host from the full hostname as part
		# of the update url.
		host, domain = self.hostname.split(".", 1)

		# Add host value to the update url.
		url = "%s/%s" % (self.url, host)

		# Send update to the server.
		try:
			response = self.send_request(url, data=data)

		# Handle error codes.
		except DDNSNotFound:
			raise DDNSRequestError(_("Invalid hostname specified"))

		# Handle success messages.
		if response.code == 200:
			return

		# If we got here, some other update error happened.
		raise DDNSUpdateError
