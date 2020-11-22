#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" toorsimtool.py: A toolkit for the Toorcamp SIM cards

	Requires the pySim libraries (http://cgit.osmocom.org/cgit/pysim/)
"""

#
# Copyright (C) 2012  Karl Koscher <supersat@cs.washington.edu>
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
# December 2014, Dieter Spaar: add OTA security for sysmoSIM SJS1

from pySim.commands import SimCardCommands
from pySim.utils import swap_nibbles, rpad, b2h, i2h, h2b
try:
	import argparse
except Exception, err:
	print "Missing argparse -- try apt-get install python-argparse"
import zipfile
import time
import struct
import binascii
import sys

# Python Cryptography Toolkit (pycrypto)

from Crypto.Cipher import DES3

#------

def hex_ber_length(data):
	dataLen = len(data) / 2
	if dataLen < 0x80:
		return '%02x' % dataLen
	dataLen = '%x' % dataLen
	lenDataLen = len(dataLen)
	if lenDataLen % 2:
		dataLen = '0' + dataLen
		lenDataLen = lenDataLen + 1
	return ('%02x' % (0x80 + (lenDataLen / 2))) + dataLen

def get_keys_from_file(iccid, args):
        import csv
        f = open(args.keyfile, 'r')
        cr = csv.DictReader(f)
        for row in cr:
                if row['ICCID'] == iccid:
                        args.kic = row['KIC1']
                        args.kid = row['KID1']
                        break;
        f.close()


class AppLoaderCommands(object):
	def __init__(self, transport, cla="A0", selectp2_read="00", selectp2_write="00", apdu_counter=0, msl1 = 6, msl2 = 1, keyset = 1):
		self._tp = transport
		self._cla_byte = cla
		self._selectp2_read_byte = selectp2_read
		self._selectp2_write_byte = selectp2_write		
		self._apduCounter = apdu_counter
		self._msl1 = msl1
		self._msl2 = msl2;
		self._keyset = keyset;

	def test_rfm(self, SIMCard=True):

		# use only one of the following
		if (SIMCard==True):
			# SIM: select MF/GSM/EF_IMSI and read content (9 bytes) (requires keyset one or three depending on the SIM card spec)
                        read_sim_imsi_adpu = 'A0A40000023F00' + 'A0A40000027F20' + 'A0A40000026F07' + 'A0B0000009'
			# SIM: select MF/GSM/EF_SPN and read content (11 bytes) (requires keyset one or three depending on the SIM card spec)
                        read_sim_spn_adpu = 'A0A40000023F00' + 'A0A40000027F20' + 'A0A40000026F46' + 'A0B0000011'
			# SIM: select MF/GSM/EF_SPN and write content (11 bytes) (requires keyset one or three depending on the SIM card spec)
                        write_sim_spn_adpu = 'A0A40004023F00' + 'A0A40004027F20' + 'A0A40004026F46' + 'A0d6000011006d6f6e6f676f746fffffffffffffffff'
                        
                        print 'RFM SIM: Read IMSI'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_sim(read_sim_imsi_adpu);
			else:
				self.send_wrapped_apdu_rfm_sim(read_sim_imsi_adpu);

                        print 'RFM SIM: Read SPN'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_sim(read_sim_spn_adpu);
			else:
				self.send_wrapped_apdu_rfm_sim(read_sim_spn_adpu);

                        print 'RFM SIM: Write SPN'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_sim(write_sim_spn_adpu);
			else:
				self.send_wrapped_apdu_rfm_sim(write_sim_spn_adpu);
		else:
			# USIM: select MF/GSM/EF_IMSI and read content (9 bytes) (requires keyset one or three depending on the SIM card spec)
                        read_uicc_imsi_adpu = '00A40004023F00' + '00A40004027F20' + '00A40004026F07' + '00B0000009'
			# USIM: select MF/GSM/EF_SPN and read content (11 bytes) (requires keyset one or three depending on the SIM card spec)
                        read_uicc_spn_adpu = '00A40004023F00' + '00A40004027F20' + '00A40004026F46' + '00B0000011'                        
			# USIM: select MF/GSM/EF_SPN and write content (11 bytes) (requires keyset one or three depending on the SIM card spec)
                        write_uicc_spn_adpu = '00A40004023F00' + '00A40004027F20' + '00A40004026F46' + '00d6000011006d6f6e6f676f746fffffffffffffffff'
                    
                        print 'RFM UICC: Read IMSI'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_usim(read_uicc_imsi_adpu);
			else:
				self.send_wrapped_apdu_rfm_usim(read_uicc_imsi_adpu);

                        print 'RFM UICC: Read SPN'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_usim(read_uicc_spn_adpu);
			else:
				self.send_wrapped_apdu_rfm_usim(read_uicc_spn_adpu);

                        print 'RFM UICC: Write SPN'
			if not args.smpp:
				print self.send_wrapped_apdu_rfm_usim(write_uicc_spn_adpu);
			else:
				self.send_wrapped_apdu_rfm_usim(write_uicc_spn_adpu);
		return;

	def send_terminal_profile(self, Verbose=False):
            
                if Verbose:
                    print "Sending terminal profile"            

		#rv = self._tp.send_apdu('A010000011FFFF000000000000000000000000000000') # sysmocom SIM et al
		# rv = self._tp.send_apdu('A010000009FFFFF7FFFFFFFFFFFF') # mimic what G+D JLoad is sending by default
		rv = self._tp.send_apdu('8010000009130180020000000000') # mimic what SimAllianceLoader is sending by default
		
		# In case of "91xx" -> Fetch data, execute cmd and reply with terminal response
		while "91" == rv[1][0:2]:
			rv = self._tp.send_apdu('80120000' + rv[1][2:4]) # FETCH
			if "9000" == rv[1]:
                            #rv = send_terminal_response(Verbose)
                            if Verbose:
                                print "Sending terminal response"            

                            #Send TERMINAL RESPONSE
                            #rv = self._tp.send_apdu('A01400000C810301030002028281030100') # TERMINAL RESPONSE SimAllianceLoader, sysmocom et al
                            rv = self._tp.send_apdu('80140000088103011300030100') # TERMINAL RESPONSE that makes G+D happy
		# otherwise "9300" (SIM Busy)
			
                return rv;

	def select_usim(self):
		rv = self._tp.send_apdu('00A4040007a0000000871002')
		return rv;

	# Wrap an APDU inside an SMS-PP APDU	
	def send_wrapped_apdu_internal(self, data, tar, msl1, msl2, kic_index, kid_index, MoreDataToSend):
		#
		# See ETSI TS 102 225 and ETSI TS 102 226 for more details
		# about OTA security.
		#
		# So far only no signature check, RC or CC are supported.
		# The only supported ciphering mode is "Triple DES in outer-CBC
		# mode using two different keys" which is also used for CC.

                if args.print_apdus:
                    print "APDU: " + data;
                
		# SPI first octet: set to MSL
		spi_1 = msl1;

		# length of signature

		if ((spi_1 & 0x03) == 0): # no integrity check
			len_sig = 0;
		elif ((spi_1 & 0x03) == 1): # RC
			len_sig = 4;
		elif ((spi_1 & 0x03) == 2): # CC
			len_sig = 8;
		else:
			print "Invalid spi_1"
			exit(0);
		
		using_counter = False;
		if ((spi_1 & 0x18) != 0):
			using_counter = True;                    
		
		pad_cnt = 0;
		# Padding if Ciphering is used
		if ((spi_1 & 0x04) != 0): # check ciphering bit
			len_cipher = 6 + len_sig + (len(data) / 2)
			pad_cnt = 8 - (len_cipher % 8) # 8 Byte blocksize for DES-CBC (TODO: different padding)
			# TODO: there is probably a better way to add "pad_cnt" padding bytes
			for i in range(0, pad_cnt):
				data = data + '00';

		# CHL + SPI first octet
		part_head = ('%02x' % (0x0D + len_sig)) + ('%02x' % (spi_1))

		Kic = '00';
		KID = '00';
		if ((spi_1 & 0x04) != 0): # check ciphering bit
			Kic = ('%02x' % (0x05 + (kic_index << 4))) # 05: Triple DES in outer-CBC mode using two different keys
		if ((spi_1 & 0x03) == 2): # CC
			KID = ('%02x' % (0x05 + (kid_index << 4))) # 05: Triple DES in outer-CBC mode using two different keys

                if args.print_apdus:
                    print "TAR: " + tar + " SPI: %02x %02x" %(msl1, msl2) + " KIC/KID: %s %s" %(Kic, KID);

		# SPI second octet (01: POR required) + Kic + KID + TAR
		# TODO: depending on the returned data use ciphering (10) and/or a signature (08)
		part_head = part_head + ('%02x' % (msl2)) + Kic + KID + tar;
                # print "part_head: " + part_head;
                
		# CNTR + PCNTR (CNTR not used)
		if using_counter:
                    cnt = self._apduCounter; 
                else: 
                    cnt = 0;

		part_cnt = '00' + ('%08x' % (cnt)) + ('%02x' % (pad_cnt))
                # print "part_cnt: " + part_cnt;
                
                if using_counter:
                    print "CNTR: %d - 00%08x" %(cnt, cnt);
                    cnt += 1;
                    self._apduCounter = cnt;
                
		envelopeData = part_head + part_cnt + data;
                # print "envelopeData: " + envelopeData;

		# two bytes CPL, CPL is part of RC/CC/DS
		envelopeData = ('%04x' % (len(envelopeData) / 2 + len_sig)) + envelopeData

		if (len_sig == 8):
			# Padding
			temp_data = envelopeData
			len_cipher = (len(temp_data) / 2)
			pad_cnt = 8 - (len_cipher % 8) # 8 Byte blocksize for DES-CBC  (TODO: add different padding)
			# TODO: there is probably a better way to add "pad_cnt" padding bytes
			for i in range(0, pad_cnt):
				temp_data = temp_data + '00';

			key = binascii.a2b_hex(args.kid);
			iv = binascii.a2b_hex('0000000000000000');
			cipher = DES3.new(key, DES3.MODE_CBC, iv);
			ciph = cipher.encrypt(binascii.a2b_hex(temp_data));
			envelopeData = part_cnt + binascii.b2a_hex(ciph[len(ciph) - 8:]) + data;
		elif (len_sig == 4):
			crc32 = binascii.crc32(binascii.a2b_hex(envelopeData))
			envelopeData = part_cnt + ('%08x' % (crc32 & 0xFFFFFFFF)) + data;
		elif (len_sig == 0):
			envelopeData = part_cnt + data;
		else:
			print "Invalid len_sig"
			exit(0)

		# Ciphering (CNTR + PCNTR + RC/CC/DS + data)

		if ((spi_1 & 0x04) != 0): # check ciphering bit
			key = binascii.a2b_hex(args.kic);
			iv = binascii.a2b_hex('0000000000000000');
			cipher = DES3.new(key, DES3.MODE_CBC, iv);
			ciph = cipher.encrypt(binascii.a2b_hex(envelopeData));
			envelopeData = part_head + binascii.b2a_hex(ciph)
		else:
			envelopeData = part_head + envelopeData;

		# -------------------------------------------------------------

		# Command (add UDHI: USIM Toolkit Security Header)
		# TS 23.048
		#
		#   02: UDHDL
		#   70: IEIA (CPI=70)
		#   00: IEIDLa
		#
		# two bytes CPL
		# no CHI
		#
		envelopeData = '027000' + ('%04x' % (len(envelopeData) / 2)) + envelopeData;

		# For sending via SMPP, those are the data which can be put into
		# the "hex" field of the "sendwp" XML file (see examples in libsmpp34).

		if args.smpp:
			print "SMPP: " + envelopeData;
			if not args.smtpdu:
				return ('00', '9000');

		# SMS-TDPU header: MS-Delivery, (no) more messages, TP-UD header, no reply path,
		# TP-OA = TON/NPI 55667788, TP-PID = SIM Download, BS timestamp
		if MoreDataToSend:
			envelopeData = '400881556677887ff600112912000004' + ('%02x' % (len(envelopeData) / 2)) + envelopeData;
		else:
			envelopeData = '440881556677887ff600112912000004' + ('%02x' % (len(envelopeData) / 2)) + envelopeData;

		if args.smtpdu:
			print "TPDU: " + envelopeData;
			if args.smpp:
				return ('00', '9000');

                # 3GPP TS 31.111 / ETSI TS 131 111 chapter 7.1.1.2 Structure of ENVELOPE (SMS-PP DOWNLOAD)
		# TS 102 232 chapter 8.7: Tag (82) Device Identities: (83) Network to (81) USIM
		# TS 131 111 chapter 9.3: Tag (8b) SMS-TPDU 
		envelopeData = '820283818B' + hex_ber_length(envelopeData) + envelopeData		
		# TS 131 111 chapter 9.1: d1 = SMS-PP Download, d2 = Cell Broadcast Download
		envelopeData = 'd1' + hex_ber_length(envelopeData) + envelopeData;
		# Sending an ENVELOPE command to SIM: CLA A0h|INS C2h|P1 00h|P2 00h|LEN|DATA
		(response, sw) = self._tp.send_apdu('80c20000' + ('%02x' % (len(envelopeData) / 2)) + envelopeData)
               
                # Status word 0x9eXX -> send GET RESPONSE command
		if "9e" == sw[0:2]: # G+D cards: more bytes available (?? for error ??)
                        # Sending GET RESPONSE to SIM: CLA A0h|INS C0h|P1 00h|P2 00h
			(response, sw) = self._tp.send_apdu_checksw('80C00000' + sw[2:4]) # get response data for the ENVELOPE command			
		else:                    
                # Status word 0x91XX of proactive SIM -> send FETCH command                    
                    while "91" == sw[0:2]:
                        # Sending FETCH PROACTIVE COMMAND to SIM: CLA A0h|INS 12h|P1 00h|P2 00h
                        (data, sw) = self._tp.send_apdu_checksw('80120000' + sw[2:4]) # fetch response data for the ENVELOPE command                        
                        if "9000" == sw: # FETCH successful - send terminal response
                            response = response + data #TODO extract the payload out of data brefore adding it to the response
                            (data, sw) = self._tp.send_apdu('801400000C810301130082028281830100') # TERMINAL RESPONSE

                    #TODO different response unwrap required
                    
                if len(response) == 0:
			print 'No response data available'
			return ('00' , sw)
		
                #TODO check the response length for unwrapping
		# Unwrap response
		response = response[(int(response[10:12],16)*2)+12:]
		return (response[6:], response[2:6])
            
                #if len(response) == 0:
                #    return ('00' , sw)
                
		# Unwrap response
		#response = response[(int(response[10:12],16)*2)+12:]
		#return (response[6:] if response[0:1] == "02" else '00', response[2:6])

	def send_wrapped_apdu_ram(self, data, MoreDataToSend=False):
		if (len(args.kic) == 0) and (len(args.kid) == 0):
			#  TAR RAM: 000000, MSL = no security (JLM SIM), MSL2 = 1 - PoR required, keyset 0
			return self.send_wrapped_apdu_internal(data, '000000', 0, 1, 0, 0, MoreDataToSend)
		else:
			# TAR RAM: 000000, sysmoSIM SJS1: MSL = 6 CC+CR, MSL2 = 1 - PoR required, first keyset, Card Centric: MSL = 2, first keyset
			return self.send_wrapped_apdu_internal(data, '000000', self._msl1, self._msl2,  self._keyset,  self._keyset, MoreDataToSend)

	def send_wrapped_apdu_rfm_sim(self, data, MoreDataToSend=False):
		# TAR RFM SIM:  B00010, sysmoSIM SJS1: MSL = 6, firt keyset, 
		# TAR RFM SIM:  B00010, Card Centric: MSL = 2, first keyset
		return self.send_wrapped_apdu_internal(data, 'B00010', self._msl1, self._msl2,  self._keyset,  self._keyset, MoreDataToSend)

	def send_wrapped_apdu_rfm_usim(self, data, MoreDataToSend=False):
		# TAR RFM USIM: B00011, sysmoSIM SJS1: MSL = 6, first keyset
		# TAR RFM USIM: B00011, Card Centric: MSL = 2, first keyset
		return self.send_wrapped_apdu_internal(data, 'B00011', self._msl1, self._msl2,  self._keyset,  self._keyset, MoreDataToSend)

	def send_wrapped_apdu_checksw(self, data, sw="9000", MoreDataToSend=False):
                if(args.print_apdus):
                    print 'Sending Envelope Command'
		response = self.send_wrapped_apdu_ram(data, MoreDataToSend)
		if response[1] != sw:
                    raise RuntimeError("Envelope Command SW match failed! Expected %s and got %s." % (sw.lower(), response[1]))
                elif(args.print_apdus):
                    print 'Envelope Command Successful'
		return response

	def get_security_domain_aid(self):
		print "Get security domain AID"
		cla_byte = '80'; # self._cla_byte
		
		# Get Status followed by Get Response
                (data, status) = self.send_wrapped_apdu_checksw(cla_byte + 'F28000024F0000C0000000')
                print "Length of received data: %d" % len(data)

                if len(data) > 2:
                    aidlen = int(data[0:2],16) * 2
                    aid = data[2:aidlen + 2]
                    state = data[aidlen + 2:aidlen + 4]
                    privs = data[aidlen + 4:aidlen + 6]
                    print 'Security Domain AID: ' + aid + ', State: ' + state + ', Privs: ' + privs
                    return data[2:(int(data[0:2],16)*2)+2]

                return status

	def get_applets_list(self):
		print "List applets"
		cla_byte = '80'; # self._cla_byte
		
		(data, status) = self.send_wrapped_apdu_ram(cla_byte + 'f21000024f0000c0000000')
		#print "Status %s" % status
		if(status == '6310'):                    
			print "Reading data blocks"
        
		while status == '6310': # More data available. Send command again with request for "next occurrences".
			sys.stdout.write('.')
			sys.stdout.flush()
			(partData, status) = self.send_wrapped_apdu_ram(cla_byte + 'f21001024f0000c0000000')
			data = data + partData
			
        	print ' '
		#print "Status %s" % status
		print "Length of received data: %d" % len(data)
		while len(data) > 2:
			aidlen = int(data[0:2],16) * 2
			aid = data[2:aidlen + 2]
			state = data[aidlen + 2:aidlen + 4]
			privs = data[aidlen + 4:aidlen + 6]
			num_instances = int(data[aidlen + 6:aidlen + 8], 16)
			print 'AID: ' + aid + ', State: ' + state + ', Privs: ' + privs
			data = data[aidlen + 8:]
			while num_instances > 0:
				aidlen = int(data[0:2],16) * 2
				aid = data[2:aidlen + 2]
				print "\tInstance AID: " + aid
				data = data[aidlen + 2:]
				num_instances = num_instances - 1
            

	def delete_aid(self, aid, delete_related=True):

		print 'Deleting AID: ' + aid

		aidDesc = '4f' + ('%02x' % (len(aid) / 2)) + aid
		apdu = '80e400' + ('80' if delete_related else '00') + ('%02x' % (len(aidDesc) / 2)) + aidDesc + '00c0000000'
		return self.send_wrapped_apdu_checksw(apdu)

	def load_aid_raw(self, aid, executable, codeSize, volatileDataSize = 0, nonvolatileDataSize = 0):
		
		print 'Loading AID: %s Code size: %d V-MEM size: %d NV-MEM size:%d' %(aid, codeSize, volatileDataSize, nonvolatileDataSize)

		loadParameters = 'c602' + ('%04x' % codeSize)
		if volatileDataSize > 0:
			loadParameters = loadParameters + 'c702' ('%04x' % volatileDataSize)
		if nonvolatileDataSize > 0:
			loadParameters = loadParameters + 'c802' ('%04x' % nonvolatileDataSize)
		loadParameters = 'ef' + ('%02x' % (len(loadParameters) / 2)) + loadParameters

		MoreDataToSend = True;
		
		# Install for load APDU, no security domain or hash specified
		print 'Install for load APDU. No security domain or hash specified'
		data = ('%02x' % (len(aid) / 2)) + aid + '0000' + ('%02x' % (len(loadParameters) / 2)) + loadParameters + '0000'
		self.send_wrapped_apdu_checksw('80e60200' + ('%02x' % (len(data) / 2)) + data + '00c0000000', "9000", MoreDataToSend)

		# Load APDUs
		loadData = 'c4' + hex_ber_length(executable) + executable
		loadBlock = 0
		sizeSent = 0
		sizeLoadData = len(loadData) / 2

		print "-- size loadData = %d (0x%X)" % (sizeLoadData, sizeLoadData)

		blockSize = 0x88; # in hex chars

		print "-- blockSize in bytes = %d (0x%X)" % (blockSize / 2, blockSize / 2)

		while len(loadData):
			loadBlockSent = loadBlock
			if len(loadData) > blockSize:
				size = blockSize / 2
				# APDU "LOAD"
				apdu = '80e800' + ('%02x' % loadBlock) + ('%02x' % (blockSize / 2)) + loadData[:blockSize]
				loadData = loadData[blockSize:]
				loadBlock = loadBlock + 1
			else:
				size = len(loadData) / 2
				# APDU "LOAD for last block"
				apdu = '80e880' + ('%02x' % loadBlock) + ('%02x' % (len(loadData) / 2)) + loadData
				loadData = ''

			sizeSent = sizeLoadData - (len(loadData) / 2)
			print "-- loadBlock = %d  sizeSent = %d (0x%X)  size = %d (0x%X)" % (loadBlockSent, sizeSent, sizeSent, size, size)

			self.send_wrapped_apdu_checksw(apdu + '00c0000000')
	
	def generate_load_file(self, capfile):
		zipcap = zipfile.ZipFile(capfile)
		zipfiles = zipcap.namelist()

		header = None
		directory = None
		impt = None
		applet = None
		clas = None
		method = None
		staticfield = None
		export = None
		constpool = None
		reflocation = None

		for i, filename in enumerate(zipfiles):
			if filename.lower().endswith('header.cap'):
				header = zipcap.read(filename)
			elif filename.lower().endswith('directory.cap'):
				directory = zipcap.read(filename)
			elif filename.lower().endswith('import.cap'):
				impt = zipcap.read(filename)
			elif filename.lower().endswith('applet.cap'):
				applet = zipcap.read(filename)
			elif filename.lower().endswith('class.cap'):
				clas = zipcap.read(filename)
			elif filename.lower().endswith('method.cap'):
				method = zipcap.read(filename)
			elif filename.lower().endswith('staticfield.cap'):
				staticfield = zipcap.read(filename)
			elif filename.lower().endswith('export.cap'):
				export = zipcap.read(filename)
			elif filename.lower().endswith('constantpool.cap'):
				constpool = zipcap.read(filename)
			elif filename.lower().endswith('reflocation.cap'):
				reflocation = zipcap.read(filename)

		data = header.encode("hex")
		if directory:
			data = data + directory.encode("hex")
		if impt:
			data = data + impt.encode("hex")
		if applet:
			data = data + applet.encode("hex")
		if clas:
			data = data + clas.encode("hex")
		if method:
			data = data + method.encode("hex")
		if staticfield:
			data = data + staticfield.encode("hex")
		if export:
			data = data + export.encode("hex")
		if constpool:
			data = data + constpool.encode("hex")
		if reflocation:
			data = data + reflocation.encode("hex")

		return data

	def get_aid_from_load_file(self, data):
		return data[26:26+(int(data[24:26],16)*2)]
		 
	def load_app(self, capfile):
		data = self.generate_load_file(capfile)
		aid = self.get_aid_from_load_file(data)
		self.load_aid_raw(aid, data, len(data) / 2)

	def install_app(self, args):
		loadfile = self.generate_load_file(args.install)
		aid = self.get_aid_from_load_file(loadfile)

		print 'Installing CAP AID: %s Module AID: %s Instance AID: %s' %(aid,args.module_aid,args.instance_aid)

		toolkit_params = ''
		if args.enable_sim_toolkit:
			assert len(args.access_domain) % 2 == 0
			assert len(args.priority_level) == 2
			toolkit_params = ('%02x' % (len(args.access_domain) / 2))  + args.access_domain
			toolkit_params = toolkit_params + args.priority_level + ('%02x' % args.max_timers)
			toolkit_params = toolkit_params + ('%02x' % args.max_menu_entry_text)
			toolkit_params = toolkit_params + ('%02x' % args.max_menu_entries) + '0000' * args.max_menu_entries
			toolkit_params = toolkit_params + ('%02x' % args.max_channels) + '00' #trailing '00' is the min. security level
			if args.tar:
				assert len(args.tar) % 6 == 0
				toolkit_params = toolkit_params + ('%02x' % (len(args.tar) / 2)) + args.tar
			toolkit_params = 'ca' + ('%02x' % (len(toolkit_params) / 2)) + toolkit_params

		assert len(args.nonvolatile_memory_required) == 4
		assert len(args.volatile_memory_for_install) == 4
		parameters = 'c802' + args.nonvolatile_memory_required + 'c702' + args.volatile_memory_for_install
		if toolkit_params:
			parameters = parameters + toolkit_params
		parameters = 'ef' + ('%02x' % (len(parameters) / 2)) + parameters + 'c9' + ('%02x' % (len(args.app_parameters) / 2)) + args.app_parameters
		
		data = ('%02x' % (len(aid) / 2)) + aid + ('%02x' % (len(args.module_aid) / 2)) + args.module_aid + ('%02x' % (len(args.instance_aid) / 2)) + \
			   args.instance_aid + '0100' + ('%02x' % (len(parameters) / 2)) + parameters + '00'
		self.send_wrapped_apdu_checksw('80e60c00' + ('%02x' % (len(data) / 2)) + data + '00c0000000')
#------

parser = argparse.ArgumentParser(description='Tool for Sysmocom SIMs.')
parser.add_argument('-s', '--serialport')
parser.add_argument('-p', '--pcsc', nargs='?', const=0, type=int)
parser.add_argument('-d', '--delete-app')
parser.add_argument('-l', '--load-app')
parser.add_argument('-i', '--install')
parser.add_argument('--module-aid')
parser.add_argument('--instance-aid')
parser.add_argument('--security-domain-aid')
parser.add_argument('--nonvolatile-memory-required', default='0000')
parser.add_argument('--volatile-memory-for-install', default='0000')
parser.add_argument('--enable-sim-toolkit', action='store_true')
parser.add_argument('--access-domain', default='ff')
parser.add_argument('--priority-level', default='01')
parser.add_argument('--max-timers', type=int, default=0)
parser.add_argument('--max-menu-entry-text', type=int, default=16)
parser.add_argument('--max-menu-entries', type=int, default=0)
parser.add_argument('--max-channels', type=int, default=0)
parser.add_argument('--app-parameters', default='')
parser.add_argument('--print-info', action='store_true')
parser.add_argument('-n', '--new-card-required', action='store_true')
parser.add_argument('-z', '--sleep_after_insertion', type=float, default=0.0)
parser.add_argument('--disable-pin')
parser.add_argument('--pin')
parser.add_argument('--adm')
parser.add_argument('-t', '--list-applets', action='store_true')
parser.add_argument('--tar')
parser.add_argument('--msl1', type=int, default=6)
parser.add_argument('--msl2', type=int, default=1)
parser.add_argument('--keyset', type=int, default=1)
parser.add_argument('--cla', default='80')
parser.add_argument('--counter', type=int, default=0)
parser.add_argument('--dump-phonebook', action='store_true')
parser.add_argument('--set-phonebook-entry', nargs=4)
parser.add_argument('--kic', default='')
parser.add_argument('--kid', default='')
parser.add_argument('--smpp', action='store_true')
parser.add_argument('--smtpdu', action='store_true')
parser.add_argument('--keyfile', default='sysmocom_sim_data.csv')
parser.add_argument('--show-cap-aid')
parser.add_argument('-A','--print-apdus', action='store_true')        
parser.add_argument('-v','--verbose', action='store_true')        

args = parser.parse_args()

if args.show_cap_aid is not None:
	class DummySL:
		pass
	sl = DummySL()
	pass
        
        ac = AppLoaderCommands(transport=sl)

        loadfile = ac.generate_load_file(args.show_cap_aid)
        aid = ac.get_aid_from_load_file(loadfile)

        print 'CAP file %s has AID %s' % (args.show_cap_aid, aid)
        exit(0)

if args.pcsc is not None:
	from pySim.transport.pcsc import PcscSimLink
	# print (args.pcsc)
	# print (args.print_apdus)
	sl = PcscSimLink(args.pcsc)
elif args.serialport is not None:
	from pySim.transport.serial import SerialSimLink
	sl = SerialSimLink(device=args.serialport, baudrate=9600)
elif args.smpp is not None:
	class DummySL:
		pass
	sl = DummySL()
	pass
else:
	raise RuntimeError("Need to specify either --serialport, --pcsc or --smpp")

sc = SimCardCommands(transport=sl)
ac = AppLoaderCommands(transport=sl,cla=args.cla,msl1=args.msl1,msl2=args.msl2,keyset=args.keyset,apdu_counter=args.counter)

if not args.smpp:
	sl.wait_for_card(newcardonly=args.new_card_required)
	time.sleep(args.sleep_after_insertion)

if not args.smpp:   
        if args.verbose:
            print "Reading card ICCID"           
	iccid = swap_nibbles(sc.read_binary(['3f00', '2fe2'])[0])
	print "ICCID: %s" % iccid
	#print "ICCID: " + swap_nibbles(sc.read_binary(['3f00', '2fe2'])[0])
	ac.select_usim()
	ac.send_terminal_profile(args.verbose)
	
	if (len(args.kic) == 0) and (len(args.kid) == 0):
            if args.verbose:
                print "No keys provided. Trying to find them in %s" % args.keyfile            
            get_keys_from_file(iccid.rstrip('f'), args)
            if (len(args.kic) == 0) and (len(args.kid) == 0):
                print "KIC and KID not found in %s for ICCID" % args.keyfile
            else:
                if args.verbose:
                    print "Found OTA keys in %s for ICCID" % args.keyfile
                print "KIC: %s" % args.kic
                print "KID: %s" % args.kid        
        #there are things that can still be done w/o keys after this point
else:
    if not args.kid or not args.kic:
        print "Warning: no KID or KIC provided for SMPP mode"           

# for access testing
# print "Testing RFM"
# ac.test_rfm(False)#SIM
# ac.test_rfm(True)#USIM
# exit(0)
        
if args.pin:
    	print "Verify PIN1"
	data, sw = sc.verify_chv(1, args.pin)
	if sw == '9000':
            print "Passed - %s" % sw
        else:
            print "Failed - %s" % sw

if args.adm:
	print "Verify ADM1"
        adm = args.adm if len(args.adm) <= 8 else h2b(args.adm)
	data, sw = sc.verify_chv(0x0A,adm)
	if sw == '9000':
            print "Passed - %s" % sw
        else:
            print "Failed - %s" % sw

if args.delete_app:
	print "Delete applet"
	ac.delete_aid(args.delete_app)

if args.load_app:
	print "Load applet"
	ac.load_app(args.load_app)

if args.install:
	print "Install applet"
	ac.install_app(args)

if args.print_info:
	print "--print-info not implemented yet."

if args.disable_pin:
	sl.send_apdu_checksw('0026000108' + args.disable_pin.encode("hex") + 'ff' * (8 - len(args.disable_pin)))

if args.dump_phonebook:
	num_records = sc.record_count(['3f00','7f10','6f3a'])
	print ("Phonebook: %d records available" % num_records)
	for record_id in range(1, num_records + 1):
		print sc.read_record(['3f00','7f10','6f3a'], record_id)

if args.set_phonebook_entry:
	num_records = sc.record_count(['3f00','7f10','6f3a'])
	record_size = sc.record_size(['3f00','7f10','6f3a'])
	record_num = int(args.set_phonebook_entry[0])
	if (record_num < 1) or (record_num > num_records):
		raise RuntimeError("Invalid phonebook record number")
	encoded_name = rpad(b2h(args.set_phonebook_entry[1]), (record_size - 14) * 2)
	if len(encoded_name) > ((record_size - 14) * 2):
		raise RuntimeError("Name is too long")
	if len(args.set_phonebook_entry[2]) > 20:
		raise RuntimeError("Number is too long")
	encoded_number = swap_nibbles(rpad(args.set_phonebook_entry[2], 20))
	record = encoded_name + ('%02x' % len(args.set_phonebook_entry[2])) + args.set_phonebook_entry[3] + encoded_number + 'ffff'
	sc.update_record(['3f00','7f10','6f3a'], record_num, record)

if args.list_applets:
        ac.get_security_domain_aid()	
	ac.get_applets_list()
