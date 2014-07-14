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
import subprocess
import urllib2
import xml.dom.minidom

from i18n import _

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

	# Automatically register all providers.
	class __metaclass__(type):
		def __init__(provider, name, bases, dict):
			type.__init__(provider, name, bases, dict)

			# The main class from which is inherited is not registered
			# as a provider.
			if name == "DDNSProvider":
				return

			if not all((provider.handle, provider.name, provider.website)):
				raise DDNSError(_("Provider is not properly configured"))

			assert not _providers.has_key(provider.handle), \
				"Provider '%s' has already been registered" % provider.handle

			_providers[provider.handle] = provider

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

		# Check if we actually need to update this host.
		elif self.is_uptodate(self.protocols):
			logger.debug(_("%s is already up to date") % self.hostname)
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

			# If no addresses for the given protocol exist, we
			# are fine...
			if current_address is None and not addresses:
				continue

			if not current_address in addresses:
				return False

		return True

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

	def update(self):
		# There is no additional data required so we directly can
		# send our request.
		response = self.send_request(self.url, username=self.username, password=self.password)

		# Get the full response message.
		output = response.read()

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

	def update(self):
		scriptlet = self.__make_scriptlet()

		# -v enables TCP hence we transfer keys and other data that may
		# exceed the size of one packet.
		# -t sets the timeout
		command = ["nsupdate", "-v", "-t", "60"]

		p = subprocess.Popen(command, shell=True,
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
		)
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

		return "\n".join(scriptlet)


class DDNSProviderDHS(DDNSProvider):
	handle    = "dhs.org"
	name      = "DHS International"
	website   = "http://dhs.org/"
	protocols = ("ipv4",)

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
	handle    = "dtdns.com"
	name      = "DtDNS"
	website   = "http://dtdns.com/"
	protocols = ("ipv4",)

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


class DDNSProviderDynDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "dyndns.org"
	name      = "Dyn"
	website   = "http://dyn.com/dns/"
	protocols = ("ipv4",)

	# Information about the format of the request is to be found
	# http://http://dyn.com/support/developers/api/perform-update/
	# http://dyn.com/support/developers/api/return-codes/

	url = "https://members.dyndns.org/nic/update"


class DDNSProviderDynU(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "dynu.com"
	name      = "Dynu"
	website   = "http://dynu.com/"
	protocols = ("ipv6", "ipv4",)

	# Detailed information about the request and response codes
	# are available on the providers webpage.
	# http://dynu.com/Default.aspx?page=dnsapi

	url = "https://api.dynu.com/nic/update"

	def _prepare_request_data(self):
		data = DDNSProviderDynDNS._prepare_request_data(self)

		# This one supports IPv6
		data.update({
			"myipv6"   : self.get_address("ipv6"),
		})

		return data


class DDNSProviderEasyDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "easydns.com"
	name      = "EasyDNS"
	website   = "http://www.easydns.com/"
	protocols = ("ipv4",)

	# There is only some basic documentation provided by the vendor,
	# also searching the web gain very poor results.
	# http://mediawiki.easydns.com/index.php/Dynamic_DNS

	url = "http://api.cp.easydns.com/dyn/tomato.php"


class DDNSProviderEnomCom(DDNSResponseParserXML, DDNSProvider):
	handle    = "enom.com"
	name      = "eNom Inc."
	website   = "http://www.enom.com/"

	# There are very detailed information about how to send an update request and
	# the respone codes.
	# http://www.enom.com/APICommandCatalog/

	url = "https://dynamic.name-services.com/interface.asp"

	def update(self):
		data = {
			"command"        : "setdnshost",
			"responsetype"   : "xml",
			"address"        : self.get_address("ipv4"),
			"domainpassword" : self.password,
			"zone"           : self.hostname
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if self.get_xml_tag_value(output, "ErrCount") == "0":
			return

		# Handle error codes.
		errorcode = self.get_xml_tag_value(output, "ResponseNumber")

		if errorcode == "304155":
			raise DDNSAuthenticationError
		elif errorcode == "304153":
			raise DDNSRequestError(_("Domain not found."))

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

	def update(self):
		data = {
			"ip" : self.get_address("ipv4")
		}

		# Add auth token to the update url.
		url = "%s/%s" % (self.url, self.token)

		# Send update to the server.
		try:
			response = self.send_request(url, method="PUT", data=data)

		# Handle error codes
		except urllib2.HTTPError, e:
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

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if output.startswith("Updated") or "has not changed" in output:
			return

		# Handle error codes.
		if output == "ERROR: Unable to locate this record":
			raise DDNSAuthenticationError
		elif "is an invalid IP address" in output:
			raise DDNSRequestError(_("Invalid IP address has been sent."))

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderLightningWireLabs(DDNSProvider):
	handle    = "dns.lightningwirelabs.com"
	name      = "Lightning Wire Labs DNS Service"
	website   = "http://dns.lightningwirelabs.com/"

	# Information about the format of the HTTPS request is to be found
	# https://dns.lightningwirelabs.com/knowledge-base/api/ddns

	url = "https://dns.lightningwirelabs.com/update"

	def update(self):
		data =  {
			"hostname" : self.hostname,
			"address6" : self.get_address("ipv6", "-"),
			"address4" : self.get_address("ipv4", "-"),
		}

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

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderNamecheap(DDNSResponseParserXML, DDNSProvider):
	handle    = "namecheap.com"
	name      = "Namecheap"
	website   = "http://namecheap.com"
	protocols = ("ipv4",)

	# Information about the format of the HTTP request is to be found
	# https://www.namecheap.com/support/knowledgebase/article.aspx/9249/0/nc-dynamic-dns-to-dyndns-adapter
	# https://community.namecheap.com/forums/viewtopic.php?f=6&t=6772

	url = "https://dynamicdns.park-your-domain.com/update"

	def update(self):
		# Namecheap requires the hostname splitted into a host and domain part.
		host, domain = self.hostname.split(".", 1)

		data = {
			"ip"       : self.get_address("ipv4"),
			"password" : self.password,
			"host"     : host,
			"domain"   : domain
		}

		# Send update to the server.
		response = self.send_request(self.url, data=data)

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if self.get_xml_tag_value(output, "IP") == self.get_address("ipv4"):
			return

		# Handle error codes.
		errorcode = self.get_xml_tag_value(output, "ResponseNumber")

		if errorcode == "304156":
			raise DDNSAuthenticationError
		elif errorcode == "316153":
			raise DDNSRequestError(_("Domain not found."))
		elif errorcode == "316154":
			raise DDNSRequestError(_("Domain not active."))
		elif errorcode in ("380098", "380099"):
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderNOIP(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "no-ip.com"
	name      = "No-IP"
	website   = "http://www.no-ip.com/"
	protocols = ("ipv4",)

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


class DDNSProviderNsupdateINFO(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "nsupdate.info"
	name      = "nsupdate.info"
	website   = "http://www.nsupdate.info/"
	protocols = ("ipv6", "ipv4",)

	# Information about the format of the HTTP request can be found
	# after login on the provider user intrface and here:
	# http://nsupdateinfo.readthedocs.org/en/latest/user.html

	# Nsupdate.info uses the hostname as user part for the HTTP basic auth,
	# and for the password a so called secret.
	@property
	def username(self):
		return self.get("hostname")

	@property
	def password(self):
		return self.get("secret")

	@property
	def proto(self):
		return self.get("proto")

	@property
	def url(self):
		# The update URL is different by the used protocol.
		if self.proto == "ipv4":
			return "https://ipv4.nsupdate.info/nic/update"
		elif self.proto == "ipv6":
			return "https://ipv6.nsupdate.info/nic/update"
		else:
			raise DDNSUpdateError(_("Invalid protocol has been given"))

	def _prepare_request_data(self):
		data = {
			"myip" : self.get_address(self.proto),
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

	@property
	def proto(self):
		return self.get("proto")

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(self.proto)
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

	def _prepare_request_data(self):
		data = DDNSProtocolDynDNS2._prepare_request_data(self)
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
		if not data.has_key("ipv6") and not data.has_key("ipv4"):
			raise DDNSConfigurationError

		# Check if a token has been set.
		if self.token:
			data["token"] = self.token

		# Raise an error if no token and no useranem and password
		# are given.
		elif not self.username and not self.password:
			raise DDNSConfigurationError(_("No Auth details specified."))

		# HTTP Basic Auth is only allowed if no token is used.
		if self.token:
			# Send update to the server.
			response = self.send_request(self.url, data=data)
		else:
			# Send update to the server.
			response = self.send_request(self.url, username=self.username, password=self.password,
				data=data)

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if "100" in output or "101" in output:
			return

		# Handle error codes.
		if "401" or "402" in output:
			raise DDNSAuthenticationError
		elif "408" in output:
			raise DDNSRequestError(_("Invalid IPv4 address has been sent."))
		elif "409" in output:
			raise DDNSRequestError(_("Invalid IPv6 address has been sent."))
		elif "412" in output:
			raise DDNSRequestError(_("No valid FQDN was given."))
		elif "414" in output:
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError


class DDNSProviderSelfhost(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "selfhost.de"
	name      = "Selfhost.de"
	website   = "http://www.selfhost.de/"
	protocols = ("ipv4",)

	url = "https://carol.selfhost.de/nic/update"

	def _prepare_request_data(self):
		data = DDNSProviderDynDNS._prepare_request_data(self)
		data.update({
			"hostname" : "1",
		})

		return data


class DDNSProviderSPDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "spdns.org"
	name      = "SPDNS"
	website   = "http://spdns.org/"
	protocols = ("ipv4",)

	# Detailed information about request and response codes are provided
	# by the vendor. They are using almost the same mechanism and status
	# codes as dyndns.org so we can inherit all those stuff.
	#
	# http://wiki.securepoint.de/index.php/SPDNS_FAQ
	# http://wiki.securepoint.de/index.php/SPDNS_Update-Tokens

	url = "https://update.spdns.de/nic/update"


class DDNSProviderStrato(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "strato.com"
	name      = "Strato AG"
	website   = "http:/www.strato.com/"
	protocols = ("ipv4",)

	# Information about the request and response can be obtained here:
	# http://www.strato-faq.de/article/671/So-einfach-richten-Sie-DynDNS-f%C3%BCr-Ihre-Domains-ein.html

	url = "https://dyndns.strato.com/nic/update"


class DDNSProviderTwoDNS(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "twodns.de"
	name      = "TwoDNS"
	website   = "http://www.twodns.de"
	protocols = ("ipv4",)

	# Detailed information about the request can be found here
	# http://twodns.de/en/faqs
	# http://twodns.de/en/api

	url = "https://update.twodns.de/update"

	def _prepare_request_data(self):
		data = {
			"ip" : self.get_address("ipv4"),
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

	@property
	def proto(self):
		return self.get("proto")

	def _prepare_request_data(self):
		data = {
			"hostname" : self.hostname,
			"myip"     : self.get_address(self.proto)
		}

		return data


class DDNSProviderZoneedit(DDNSProtocolDynDNS2, DDNSProvider):
	handle    = "zoneedit.com"
	name      = "Zoneedit"
	website   = "http://www.zoneedit.com"
	protocols = ("ipv4",)

	# Detailed information about the request and the response codes can be
	# obtained here:
	# http://www.zoneedit.com/doc/api/other.html
	# http://www.zoneedit.com/faq.html

	url = "https://dynamic.zoneedit.com/auth/dynamic.html"

	@property
	def proto(self):
		return self.get("proto")

	def update(self):
		data = {
			"dnsto" : self.get_address(self.proto),
			"host"  : self.hostname
		}

		# Send update to the server.
		response = self.send_request(self.url, username=self.username, password=self.password,
			data=data)

		# Get the full response message.
		output = response.read()

		# Handle success messages.
		if output.startswith("<SUCCESS"):
			return

		# Handle error codes.
		if output.startswith("invalid login"):
			raise DDNSAuthenticationError
		elif output.startswith("<ERROR CODE=\"704\""):
			raise DDNSRequestError(_("No valid FQDN was given.")) 
		elif output.startswith("<ERROR CODE=\"702\""):
			raise DDNSInternalServerError

		# If we got here, some other update error happened.
		raise DDNSUpdateError
