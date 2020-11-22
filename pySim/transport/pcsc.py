#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import NoCardException, CardRequestTimeoutException
from smartcard.System import readers

from pySim.exceptions import NoCardError
from pySim.transport import LinkBase
from pySim.utils import h2i, i2h


class PcscSimLink(LinkBase):

	def __init__(self, reader_number=0):
		r = readers();
		self._reader = r[reader_number]
		self._con = self._reader.createConnection()

	def __del__(self):
		self._con.disconnect()
		return

	def wait_for_card(self, timeout=None, newcardonly=False):
		cr = CardRequest(readers=[self._reader], timeout=timeout, newcardonly=newcardonly)
		try:
			cr.waitforcard()
		except CardRequestTimeoutException:
			raise NoCardError()
		self.connect()

	def connect(self):
		try:
			self._con.connect()
		except NoCardException:
			raise NoCardError()

	def disconnect(self):
		self._con.disconnect()

	def reset_card(self):
		self._con.disconnect()
		try:
			self._con.connect()
		except NoCardException:
			raise NoCardError()
		return 1

	def send_apdu_raw(self, pdu):
		"""see LinkBase.send_apdu_raw"""

		apdu = h2i(pdu)
		print("apdu >>> ")
		print(''.join(format(apdu, '02x') for apdu in apdu))

		data, sw1, sw2 = self._con.transmit(apdu)
		print ("response code: " + "sw1: " +str(hex(sw1)) +  " sw2: " + str(hex(sw2)))
		print (''.join(format(data, '02x') for data in data)) 
		# print("DATA: ")
		# print(hex(data))
		# print("sw1: ")
		# print(hex(sw1))
		# print("sw2: ")
		# print(hex(sw2))
		sw = [sw1, sw2]

		# Return value
		return i2h(data), i2h(sw)
