#!/usr/bin/python
###############################################################################
#                                                                             #
# ddns - A dynamic DNS client for IPFire                                      #
# Copyright (C) 2014 IPFire development team                                  #
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
import os
import sqlite3

# Initialize the logger.
import logging
logger = logging.getLogger("ddns.database")
logger.propagate = 1

class DDNSDatabase(object):
	def __init__(self, core, path):
		self.core = core
		self.path = path

		# We won't open the connection to the database directly
		# so that we do not do it unnecessarily.
		self._db = None

	def __del__(self):
		self._close_database()

	def _open_database(self, path):
		logger.debug("Opening database %s" % path)

		exists = os.path.exists(path)

		conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
		conn.isolation_level = None

		if not exists and self.is_writable():
			logger.debug("Initialising database layout")
			c = conn.cursor()
			c.executescript("""
				CREATE TABLE updates (
					hostname  TEXT NOT NULL,
					status    TEXT NOT NULL,
					message   TEXT,
					timestamp timestamp NOT NULL
				);

				CREATE TABLE settings (
					k TEXT NOT NULL,
					v TEXT NOT NULL
				);

				CREATE INDEX idx_updates_hostname ON updates(hostname);
			""")
			c.execute("INSERT INTO settings(k, v) VALUES(?, ?)", ("version", "1"))

		return conn

	def is_writable(self):
		# Check if the database file exists and is writable.
		ret = os.access(self.path, os.W_OK)
		if ret:
			return True

		# If not, we check if we are able to write to the directory.
		# In that case the database file will be created in _open_database().
		return os.access(os.path.dirname(self.path), os.W_OK)

	def _close_database(self):
		if self._db:
			self._db_close()
			self._db = None

	def _execute(self, query, *parameters):
		if self._db is None:
			self._db = self._open_database(self.path)

		c = self._db.cursor()
		try:
			c.execute(query, parameters)
		finally:
			c.close()

	def add_update(self, hostname, status, message=None):
		if not self.is_writable():
			logger.warning("Could not log any updates because the database is not writable")
			return

		self._execute("INSERT INTO updates(hostname, status, message, timestamp) \
			VALUES(?, ?, ?, ?)", hostname, status, message, datetime.datetime.utcnow())

	def log_success(self, hostname):
		logger.debug("Logging successful update for %s" % hostname)

		return self.add_update(hostname, "success")

	def log_failure(self, hostname, exception):
		if exception:
			message = "%s: %s" % (exception.__class__.__name__, exception.reason)
		else:
			message = None

		logger.debug("Logging failed update for %s: %s" % (hostname, message or ""))

		return self.add_update(hostname, "failure", message=message)

	def last_update(self, hostname, status=None):
		"""
			Returns the timestamp of the last update (with the given status code).
		"""
		if self._db is None:
			self._db = self._open_database(self.path)

		c = self._db.cursor()

		try:
			if status:
				c.execute("SELECT timestamp FROM updates WHERE hostname = ? AND status = ? \
					ORDER BY timestamp DESC LIMIT 1", (hostname, status))
			else:
				c.execute("SELECT timestamp FROM updates WHERE hostname = ? \
					ORDER BY timestamp DESC LIMIT 1", (hostname,))

			for row in c:
				return row[0]
		finally:
			c.close()

	def last_update_status(self, hostname):
		"""
			Returns the update status of the last update.
		"""
		if self._db is None:
			self._db = self._open_database(self.path)

		c = self._db.cursor()

		try:
			c.execute("SELECT status FROM updates WHERE hostname = ? \
				ORDER BY timestamp DESC LIMIT 1", (hostname,))

			for row in c:
				return row[0]
		finally:
			c.close()

	def last_update_failure_message(self, hostname):
		"""
			Returns the reason string for the last failed update (if any).
		"""
		if self._db is None:
			self._db = self._open_database(self.path)

		c = self._db.cursor()

		try:
			c.execute("SELECT message FROM updates WHERE hostname = ? AND status = ? \
				ORDER BY timestamp DESC LIMIT 1", (hostname, "failure"))

			for row in c:
				return row[0]
		finally:
			c.close()
