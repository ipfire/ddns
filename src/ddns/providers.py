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

import logging

from i18n import _

# Import all possible exception types.
from .errors import *

logger = logging.getLogger("ddns.providers")
logger.propagate = 1

class DDNSProvider(object):
	INFO = {
		# A short string that uniquely identifies
		# this provider.
		"handle"    : None,

		# The full name of the provider.
		"name"      : None,

		# A weburl to the homepage of the provider.
		# (Where to register a new account?)
		"website"   : None,

		# A list of supported protocols.
		"protocols" : ["ipv6", "ipv4"],
	}

	DEFAULT_SETTINGS = {}

	def __init__(self, core, **settings):
		self.core = core

		# Copy a set of default settings and
		# update them by those from the configuration file.
		self.settings = self.DEFAULT_SETTINGS.copy()
		self.settings.update(settings)

	def __repr__(self):
		return "<DDNS Provider %s (%s)>" % (self.name, self.handle)

	def __cmp__(self, other):
		return cmp(self.hostname, other.hostname)

	@property
	def name(self):
		"""
			Returns the name of the provider.
		"""
		return self.INFO.get("name")

	@property
	def website(self):
		"""
			Returns the website URL of the provider
			or None if that is not available.
		"""
		return self.INFO.get("website", None)

	@property
	def handle(self):
		"""
			Returns the handle of this provider.
		"""
		return self.INFO.get("handle")

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
	def protocols(self):
		return self.INFO.get("protocols")

	@property
	def token(self):
		"""
			Fast access to the token.
		"""
		return self.get("token")

	def __call__(self, force=False):
		if force:
			logger.info(_("Updating %s forced") % self.hostname)

		# Check if we actually need to update this host.
		elif self.is_uptodate(self.protocols):
			logger.info(_("%s is already up to date") % self.hostname)
			return

		# Execute the update.
		self.update()

	def update(self):
		raise NotImplementedError

	def is_uptodate(self, protos):
		"""
			Returns True if this host is already up to date
			and does not need to change the IP address on the
			name server.
		"""
		for proto in protos:
			addresses = self.core.system.resolve(self.hostname, proto)

			current_address = self.get_address(proto)

			if not current_address in addresses:
				return False

		return True

	def send_request(self, *args, **kwargs):
		"""
			Proxy connection to the send request
			method.
		"""
		return self.core.system.send_request(*args, **kwargs)

	def get_address(self, proto):
		"""
			Proxy method to get the current IP address.
		"""
		return self.core.system.get_address(proto)


class DDNSProviderDHS(DDNSProvider):
	INFO = {
		"handle"    : "dhs.org",
		"name"      : "DHS International",
		"website"   : "http://dhs.org/",
		"protocols" : ["ipv4",]
	}

	# No information about the used update api provided on webpage,
	# grabed from source code of ez-ipudate.
	url = "http://members.dhs.org/nic/hosts"

	def update(self):
		data = {
			"domain"       : self.hostname,
			"ip"           : self.get_address("ipv4"),
			"hostcmd"      : "edit",
			"hostcmdstage" : "2",
			"type"         : "4",
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password,
			data=data)

		# Handle success messages.
		if response.code == 200:
			return

		# Handle error codes.
		elif response.code == 401:
			raise DDNSAuthenticationError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDNSpark(DDNSProvider):
	INFO = {
		"handle"    : "dnspark.com",
		"name"      : "DNS Park",
		"website"   : "http://dnspark.com/",
		"protocols" : ["ipv4",]
	}

	# Informations to the used api can be found here:
	# https://dnspark.zendesk.com/entries/31229348-Dynamic-DNS-API-Documentation
	url = "https://control.dnspark.com/api/dynamic/update.php"

	def update(self):
		data = {
			"domain" : self.hostname,
			"ip"     : self.get_address("ipv4"),
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password,
			data=data)

		# Get the full response message.
		output = response.read()

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
			raise DDNSRequestError(_("No valid FQDN was given."))
		elif output == "nohost":
			raise DDNSRequestError(_("Invalid hostname specified."))
		elif output == "notdyn":
			raise DDNSRequestError(_("Hostname not marked as a dynamic host."))
		elif output == "invalid":
			raise DDNSRequestError(_("Invalid IP address has been sent."))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDtDNS(DDNSProvider):
	INFO = {
		"handle"    : "dtdns.com",
		"name"      : "DtDNS",
		"website"   : "http://dtdns.com/",
		"protocols" : ["ipv4",]
		}

	# Information about the format of the HTTPS request is to be found
	# http://www.dtdns.com/dtsite/updatespec
	url = "https://www.dtdns.com/api/autodns.cfm"

	def update(self):
		data = {
			"ip" : self.get_address("ipv4"),
			"id" : self.hostname,
			"pw" : self.password
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read()

		# Remove all leading and trailing whitespace.
		output = output.strip()

		# Handle success messages.
		if "now points to" in output:
			return

		# Handle error codes.
		if output == "No hostname to update was supplied.":
			raise DDNSRequestError(_("No hostname specified."))

		elif output == "The hostname you supplied is not valid.":
			raise DDNSRequestError(_("Invalid hostname specified."))

		elif output == "The password you supplied is not valid.":
			raise DDNSAuthenticationError

		elif output == "Administration has disabled this account.":
			raise DDNSRequestError(_("Account has been disabled."))

		elif output == "Illegal character in IP.":
			raise DDNSRequestError(_("Invalid IP address has been sent."))

		elif output == "Too many failed requests.":
			raise DDNSRequestError(_("Too many failed requests."))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderDynDNS(DDNSProvider):
	INFO = {
		"handle"    : "dyndns.org",
		"name"      : "Dyn",
		"website"   : "http://dyn.com/dns/",
		"protocols" : ["ipv4",]
	}

	# Information about the format of the request is to be found
	# http://http://dyn.com/support/developers/api/perform-update/
	# http://dyn.com/support/developers/api/return-codes/
	url = "https://members.dyndns.org/nic/update"

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address("ipv4"),
		}

		return data

	def update(self):
		data = self._prepare_request_data()

		# Send update to the server.
		response = self.send_request(self.url, data=data,
			username=self.username, password=self.password)

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if output.startswith("good") or output.startswith("nochg"):
			return

		# Handle error codes.
		if output == "badauth":
			raise DDNSAuthenticationError
		elif output == "aduse":
			raise DDNSAbuseError
		elif output == "notfqdn":
			raise DDNSRequestError(_("No valid FQDN was given."))
		elif output == "nohost":
			raise DDNSRequestError(_("Specified host does not exist."))
		elif output == "911":
			raise DDNSInternalServerError
		elif output == "dnserr":
			raise DDNSInternalServerError(_("DNS error encountered."))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderEasyDNS(DDNSProviderDynDNS):
	INFO = {
		"handle"    : "easydns.com",
		"name"      : "EasyDNS",
		"website"   : "http://www.easydns.com/",
		"protocols" : ["ipv4",]
	}

	# There is only some basic documentation provided by the vendor,
	# also searching the web gain very poor results.
	# http://mediawiki.easydns.com/index.php/Dynamic_DNS

	url = "http://api.cp.easydns.com/dyn/tomato.php"


class DDNSProviderFreeDNSAfraidOrg(DDNSProvider):
	INFO = {
		"handle"    : "freedns.afraid.org",
		"name"      : "freedns.afraid.org",
		"website"   : "http://freedns.afraid.org/",
		"protocols" : ["ipv6", "ipv4",]
		}

	# No information about the request or response could be found on the vendor
	# page. All used values have been collected by testing.
	url = "https://freedns.afraid.org/dynamic/update.php"

	@property
	def proto(self):
		return self.get("proto")

	def update(self):
		address = self.get_address(self.proto)

		data = {
			"address" : address,
		}

		# Add auth token to the update url.
		url = "%s?%s" % (self.url, self.token)

		# Send update to the server.
		response = self.send_request(url, data=data)

		if output.startswith("Updated") or "has not changed" in output:
			return

		# Handle error codes.
		if output == "ERROR: Unable to locate this record":
			raise DDNSAuthenticationError
		elif "is an invalid IP address" in output:
			raise DDNSRequestError(_("Invalid IP address has been sent."))


class DDNSProviderLightningWireLabs(DDNSProvider):
	INFO = {
		"handle"    : "dns.lightningwirelabs.com",
		"name"      : "Lightning Wire Labs",
		"website"   : "http://dns.lightningwirelabs.com/",
		"protocols" : ["ipv6", "ipv4",]
	}

	# Information about the format of the HTTPS request is to be found
	# https://dns.lightningwirelabs.com/knowledge-base/api/ddns
	url = "https://dns.lightningwirelabs.com/update"

	def update(self):
		data =  {
			"hostname" : self.hostname,
		}

		# Check if we update an IPv6 address.
		address6 = self.get_address("ipv6")
		if address6:
			data["address6"] = address6

		# Check if we update an IPv4 address.
		address4 = self.get_address("ipv4")
		if address4:
			data["address4"] = address4

		# Raise an error if none address is given.
		if not data.has_key("address6") and not data.has_key("address4"):
			raise DDNSConfigurationError

		# Check if a token has been set.
		if self.token:
			data["token"] = self.token

		# Check for username and password.
		elif self.username and self.password:
			data.update({
				"username" : self.username,
				"password" : self.password,
			})

		# Raise an error if no auth details are given.
		else:
			raise DDNSConfigurationError

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Handle success messages.
		if response.code == 200:
			return

		# Handle error codes.
		if response.code == 403:
			raise DDNSAuthenticationError
		elif response.code == 400:
			raise DDNSRequestError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderNOIP(DDNSProviderDynDNS):
	INFO = {
		"handle"    : "no-ip.com",
		"name"      : "No-IP",
		"website"   : "http://www.no-ip.com/",
		"protocols" : ["ipv4",]
	}

	# Information about the format of the HTTP request is to be found
	# here: http://www.no-ip.com/integrate/request and
	# here: http://www.no-ip.com/integrate/response

	url = "http://dynupdate.no-ip.com/nic/update"

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"address"  : self.get_address("ipv4"),
		}

		return data


class DDNSProviderOVH(DDNSProviderDynDNS):
	INFO = {
		"handle"    : "ovh.com",
		"name"      : "OVH",
		"website"   : "http://www.ovh.com/",
		"protocols" : ["ipv4",]
	}

	# OVH only provides very limited information about how to
	# update a DynDNS host. They only provide the update url
	# on the their german subpage.
	#
	# http://hilfe.ovh.de/DomainDynHost

	url = "https://www.ovh.com/nic/update"

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address("ipv4"),
			"system"   : "dyndns",
		}


class DDNSProviderSelfhost(DDNSProvider):
	INFO = {
		"handle"    : "selfhost.de",
		"name"      : "Selfhost.de",
		"website"   : "http://www.selfhost.de/",
		"protocols" : ["ipv4",],
	}

	url = "https://carol.selfhost.de/update"

	def update(self):
		data = {
			"username" : self.username,
			"password" : self.password,
			"textmodi" : "1",
		}

		response = self.send_request(self.url, data=data)

		match = re.search("status=20(0|4)", response.read())
		if not match:
			raise DDNSUpdateError


class DDNSProviderSPDNS(DDNSProviderDynDNS):
	INFO = {
		"handle"    : "spdns.org",
		"name"      : "SPDNS",
		"website"   : "http://spdns.org/",
		"protocols" : ["ipv4",]
	}

	# Detailed information about request and response codes are provided
	# by the vendor. They are using almost the same mechanism and status
	# codes as dyndns.org so we can inherit all those stuff.
	#
	# http://wiki.securepoint.de/index.php/SPDNS_FAQ
	# http://wiki.securepoint.de/index.php/SPDNS_Update-Tokens

	url = "https://update.spdns.de/nic/update"


class DDNSProviderVariomedia(DDNSProviderDynDNS):
	INFO = {
		"handle"   : "variomedia.de",
		"name"     : "Variomedia",
		"website"  : "http://www.variomedia.de/",
		"protocols" : ["ipv6", "ipv4",]
	}

	# Detailed information about the request can be found here
	# https://dyndns.variomedia.de/

	url = "https://dyndns.variomedia.de/nic/update"

	@property
	def proto(self):
		return self.get("proto")

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(self.proto)
		}
