#!/usr/bin/env python3

'''
Unofficial e-distribuzione's Smart Info cummunication library

@author Gabriele Tozzi <gabriele@tozzi.eu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
'''


import time
import attr
import struct
import serial
import logging
import datetime
import collections


NAME = 'pysmartinfo'
VERSION = '0.1'
# The only authorized ApplicationID, as stated in spec 4.2.1
APPID = b'PCMC000000XXXXXX'


class Frame:
	''' A single communication frame'''
	START = 0xf7
	MAXDATALEN = 60 - 3 # 3 = src, dst, attr
	MAXADDR = 127

	MAXUINT12 = 4095
	MAXUINT16 = 65535

	# Datastruct const
	VARLEN = None

	LOG = logging.getLogger('frame')

	def __init__(self, src, dst, attr, data):
		''' Creates a new frame
		@param src bytes: source address byte 0-127
		@param dst bytes: destination address byte 0-127
		@param attr bytes: attr byte (frame type)
		@param data bytes: packet-specific data, checksum excluded
		'''
		self._bytesParam('src', src, 1)
		self._bytesParam('dst', dst, 1)
		self._bytesParam('attr', attr, 1)
		self._bytesParam('data', data, (0,self.MAXDATALEN))

		self.received = False
		self.complete = True
		self.csum = self.calcsum()

	def _bytesParam(self, name, param, length, assign=True):
		''' Validate and optionally assign a bytes param, internal usage '''
		if type(param) is str:
			param = param.encode()
		elif type(param) is int:
			if param < 0 or param > 0xff:
				raise ValueError('int parameter must be 0-255')
			param = bytes([param])
		elif type(param) is not bytes:
			raise TypeError('{} must be bytes'.format(name))

		try:
			len(length)
		except TypeError:
			if len(param) != length:
				raise ValueError('{} must be exactly {} bytes'.format(name, length))
		else:
			if len(param) < length[0]:
				raise ValueError('{} must be {} at least {} bytes'.format(name, length[0]))
			if len(param) > length[1]:
				raise ValueError('{} must be {} at most {} bytes'.format(name, length[1]))

		if assign:
			setattr(self, name, param)
		return param

	def __repr__(self):
		if hasattr(self, 'DATASTRUCT'):
			ars = []
			for name, length in self.DATASTRUCT:
				value = getattr(self, name)
				ars.append('{}={}'.format(name, value))
			datarepr = ', '.join(ars)
		else:
			datarepr = 'd' + repr(self.data)[1:]
		return '<{}({}) s{} d{} a{} {} c0x{}>'.format(self.__class__.__name__,
			7 + len(self.data), ord(self.src), ord(self.dst), ord(self.attr),
			datarepr, self.csum.hex())

	def __bytes__(self):
		''' Returns an encoded version of packet '''
		return bytes([self.START]) + bytes([3 + len(self.data)]) + self.src \
			+ self.dst + self.attr + self.data + self.csum

	def calcsum(self):
		''' Calculate checksum
		@return bytes: the calculated checksum
		'''
		sum = ord(self.src) + ord(self.dst) + ord(self.attr)
		for byte in self.data:
			sum += byte
		csum = sum % pow(2,16)
		return struct.pack('>H', csum)


class InvalidFrameError(Exception):
	''' Exception raised when receiving an invalid frame '''
	pass


class OutFrame(Frame):
	''' Base class for outgoing frames '''
	def __init__(self, src, dst, *args):
		''' Creates the frame, see self.DATASTRUCT for arguments '''
		if len(args) != len(self.DATASTRUCT):
			raise TypeError('Expected {} arguments, got {}'.format(len(self.DATASTRUCT), len(args)))

		data = b''
		for idx, elem in enumerate(self.DATASTRUCT):
			name, length = elem
			data += self._bytesParam(name, args[idx], length)

		super().__init__(src, dst, self.ATTR, data)


class EnrolmentRequestFrame(OutFrame):
	''' (OUT) Enrolment request '''
	ATTR = 72
	DATASTRUCT = (('applicationId', 16), ('release', 12), ('serial', 16))

class AddressRequestFrame(OutFrame):
	''' (OUT) Address request '''
	ATTR = 70
	DATASTRUCT = (('applicationId', 16),)

class SmartMeterComLinkCheckRequestFrame(OutFrame):
	''' (OUT) Ping Smart Meter '''
	ATTR = 103
	DATASTRUCT = (('target', 1),)
	# Primary SM target const
	PRIMARY = 0x00
	# Production SM target const
	PRODUCTION = 0x01

class DeviceInfoRequestFrame(OutFrame):
	''' (OUT) Device Information Request '''
	ATTR = 90
	DATASTRUCT = (('infoSetCode', 1),)

class ReadRequestFrame(OutFrame):
	''' (OUT) Database Request, single table row request '''
	ATTR = 2
	DATASTRUCT = (('section', 1), ('row', 1))

class LogRequestFrame(OutFrame):
	''' (OUT) Log Request '''
	ATTR = 78
	DATASTRUCT = (('logType', 1),)


class InFrame(Frame):
	''' Base class for received frames '''

	def __init__(self, recvFrame):
		''' Creates the frame from the base RecvFrame '''
		if not isinstance(recvFrame, Frame):
			raise TypeError('recvFrame must be a frame')
		if not recvFrame.received:
			raise ValueError('recvFrame must be a received frame')
		if not recvFrame.complete:
			raise ValueError('recvFrame must be complete')

		self.src = recvFrame.src
		self.dst = recvFrame.dst
		self.attr = recvFrame.attr
		self.data = recvFrame.data
		self.csum = recvFrame.csum
		self.received = recvFrame.received
		self.complete = recvFrame.complete

		self._parseDataStruct()
		self._afterInInit()

	def _parseDataStruct(self):
		datalen = 0
		fixedlen = 0
		for name, length in self.DATASTRUCT:
			if length is self.VARLEN:
				if datalen is self.VARLEN:
					raise RuntimeError('Only one param can have variable length')
				datalen = self.VARLEN
				continue

			fixedlen += length

			if datalen is not self.VARLEN:
				datalen += length

		if datalen is not self.VARLEN and len(self.data) != datalen:
			self.LOG.error('DATA LEN MISMATCH %s/%s: %s', len(self.data), datalen, self.data)
			raise ValueError('Data len mismatch, expected {}, got {}'.format(datalen, len(self.data)))

		idx = 0
		for name, length in self.DATASTRUCT:
			if length is self.VARLEN:
				length = len(self.data) - fixedlen
			value = self.data[idx:idx+length]
			idx += length
			setattr(self, name, value)

	def _afterInInit(self):
		''' After init tasks, useful to be overridden in child '''
		pass


class EnrolmentResponseFrame(InFrame):
	''' (IN) A succesfull enrolment response '''
	ATTR = 73
	DATASTRUCT = (('applicationId', 16), ('resultCode', 1))

class AddressResponseFrame(InFrame):
	''' (IN) A succesfull address response '''
	ATTR = 71
	DATASTRUCT = (('applicationId', 16), ('address', 1))

class AckFrame(InFrame):
	''' (IN) Generic positive acnowledgment frame '''
	ATTR = 251
	DATASTRUCT = (('resultCode', 1),)
	# The only possible result code
	POSITIVE = 0x00

	def _afterInInit(self):
		super()._afterInInit()
		if self.resultCode != bytes([self.POSITIVE]):
			raise NotImplementedError('Unexpected ACK result code: {}'.format(self.resultCode))

class NAckFrame(InFrame):
	''' (IN) Generic negative acnowledgment frame '''
	ATTR = 255
	DATASTRUCT = (('resultCode', 1),)
	# Known result code explanations
	RESULTS = {
		b'\x00': 'Message not correct',
		b'\x01': 'ATTR not valid',
		b'\x02': 'not valid Parameter',
		b'\x03': 'Device not Enrolled',
		b'\x04': 'Datum not valid or Unavailable',
		b'\x05': 'Log not available',
		b'\x06': 'Buffer not available',
		b'\x07': 'Over limit transmissions',
		b'\x08': 'SI not commissioned yet',
		b'\x09': 'Auth/encryption Error',
		b'\x0a': 'Target not present in configuration',
	}

	def _afterInInit(self):
		super()._afterInInit()
		try:
			self.message = self.RESULTS[self.resultCode]
		except KeyError:
			self.message = None

class DeviceInfoResponseFrame(InFrame):
	''' (IN) A succesfull device information response '''
	ATTR = 91
	DATASTRUCT = (('infoSetCode', 1), ('siRelease', 8), ('siNid', 6),
		('modemSwStackRelease', 8), ('modemFwRelease', 2), ('siType', 1))

class ReadResponseFrame(InFrame):
	''' (IN) Database Response, single table row '''
	ATTR = 3
	DATASTRUCT = (('section', 1), ('row', 1), ('value', Frame.VARLEN), ('updDate', 3), ('updTime', 3))

class LogResponseFrame(InFrame):
	''' (IN) Log Delivery Response, header '''
	ATTR = 77
	DATASTRUCT = (('firstTime', 5), ('samples', 2), ('ti', 1), ('logType', 1), ('firstValue', 4))

class LogDataBlockFrame(InFrame):
	''' (IN) Log Delivery Response, row '''
	ATTR = 79
	DATASTRUCT = (('logType', 1), ('block', 1), ('blocks', 1), ('recordsData', Frame.VARLEN))

	def _afterInInit(self):
		super()._afterInInit()
		if len(self.recordsData) % 9:
			raise ValueError('RecordsData len must be a multiple of 9, got {}'.format(len(self.recordsData)))

		self.records = [self.recordsData[i:i+9] for i in range(0, len(self.recordsData), 9)]


class RecvFrame(Frame):
	''' Represents a still unknown frame being received, handles frame reception '''

	KNOWNATTRS = {
		EnrolmentResponseFrame.ATTR: EnrolmentResponseFrame,
		AddressResponseFrame.ATTR: AddressResponseFrame,
		AckFrame.ATTR: AckFrame,
		NAckFrame.ATTR: NAckFrame,
		DeviceInfoResponseFrame.ATTR: DeviceInfoResponseFrame,
		ReadResponseFrame.ATTR: ReadResponseFrame,
		LogResponseFrame.ATTR: LogResponseFrame,
		LogDataBlockFrame.ATTR: LogDataBlockFrame,
	}

	def __init__(self):
		self.src = b''
		self.dst = b''
		self.attr = b''
		self.data = b''
		self.csum = b''
		self.received = True
		self.complete = False
		self._status = 'waitforstart'
		self._bytes = b''

	def eat(self, byte):
		''' Eats next byte for the packet
		@param byte bytes: Single byte to eat
		@return A Frame object when packet is complete
		'''
		byte = self._bytesParam('byte', byte, 1, False)
		self._bytes += byte

		if self._status == 'waitforstart':
			if byte != bytes([self.START]):
				raise InvalidFrameError('Start byte must be 0x{:02x}, got 0x{}'.format(self.START, byte.hex()))
			self._status = 'waitfordatalen'
			return None

		if self._status == 'waitfordatalen':
			self._datalen = ord(byte)
			if self._datalen < 3:
				raise NotImplementedError('Data len is less than 3')
			elif self._datalen > self.MAXDATALEN + 3:
				raise InvalidFrameError('Data len must not exceed {}'.format(self.MAX_DLEN + 3))
			self._status = 'waitforsrc'
			return None

		if self._status == 'waitforsrc':
			self.src = byte
			self._status = 'waitfordst'
			return None

		if self._status == 'waitfordst':
			self.dst = byte
			self._status = 'waitforattr'
			return None

		if self._status == 'waitforattr':
			self.attr = byte
			self._dataremlen = self._datalen - 3
			if self._dataremlen:
				self._status = 'waitfordata'
			else:
				self._status = 'waitforcsum'
				self._csumremlen = 2
			return None

		if self._status == 'waitfordata':
			assert self._dataremlen >= 1
			self.data += byte
			self._dataremlen -= 1
			if not self._dataremlen:
				self._status = 'waitforcsum'
				self._csumremlen = 2
			return None

		if self._status == 'waitforcsum':
			assert self._csumremlen >= 1
			self.csum += byte
			self._csumremlen -= 1
			if not self._csumremlen:
				ccsum = self.calcsum()
				if self.csum != ccsum:
					raise InvalidFrameError('Expected checksum 0x{}, got 0x{}'.format(ccsum.hex(), self._csum.hex()))
				self.complete = True
				self._status = 'done'
				if ord(self.attr) in self.KNOWNATTRS:
					try:
						return self.KNOWNATTRS[ord(self.attr)](self)
					except Exception as e:
						self.LOG.error('Error while instantiating final packet: %s', e)
						self.LOG.debug(self)
						raise
				return self
			return None

		if self._status == 'done':
			raise RuntimeError('Packet is complete, cannot eat more bytes')

		raise RuntimeError('Internal error: unknown status {}'.format(self._status))

	def __bytes__(self):
		''' Returns raw bytes eaten so far '''
		return self._bytes


@attr.s(frozen=True)
class SiDeviceInfo:
	''' Holds Smart Info device info data '''
	siRelease = attr.ib()
	siNid = attr.ib()
	modemSwStackRelease = attr.ib()
	modemFwRelease = attr.ib()
	siType = attr.ib()

@attr.s(frozen=True)
class TableRow:
	''' Holds table row data '''
	table = attr.ib()
	row = attr.ib()
	value = attr.ib()
	updated = attr.ib()
	descr = attr.ib()


class NAckError(RuntimeError):
	''' Raised when a NACK is received '''

	def __init__(self, code, message):
		self.code = code
		self.message = message
		super().__init__('{}: {}'.format(self.code, self.message))


class AB:
	''' SmartInfo serial Additional Block (client) implementation

	@warning Packets with wrong checksum are ignored, data is big-endian

	Steps to establish communication:
	1. Send Enrollment request
	'''

	DEFBAUD = 57600
	DEFBYTESIZE = serial.EIGHTBITS
	DEFPARITY = serial.PARITY_NONE
	DEFSTOPBITS = serial.STOPBITS_ONE
	BASETIMEOUT = .1

	# Fixed Smart Info address
	SIADDR = 127

	# Table row info
	TABLES = collections.OrderedDict([
		(100, collections.OrderedDict([
			(1, ('E(p) Total active energy of previous period', 'EEnergy')),
			(6, ('E(t) Total active energy of actual period', 'EEnergy')),
			(7, ('Et1(t) Active energy in T1 of the current period', 'EEnergy')),
			(8, ('Et2(t) Active energy in T2 of the current period', 'EEnergy')),
			(9, ('Et3(t) Active energy in T3 of the current period', 'EEnergy')),
			(10, ('Et4(t) Active energy in T4 of the current period', 'EEnergy')),
			(21, ('DATE', 'EDate')),
			(22, ('TIME', 'ETime')),
			(23, ('Daylight disabled/enabled', 'EByte')),
			(24, ('Tall Time of alarm', 'ETimeA')),
			(25, ('TypAl Type of Alarm', 'EByte')),
			(29, ('DATE_F End data billing', 'ETimeB')),
			(30, ('Tariff code', 'EByte')),
			(36, ('E-(t) Total negative active energy of actual period', 'EEnergy')),
			(50, ('Ra(t) Total value of positive reactive energy in the current period', 'EEnergy')),
			(101, ('Total daily active energy current date', 'ESEnergy')),
			(105, ('Instant Power (Average in Time Tx, 1 second) - PTx', 'EPower')),
			(106, ('Button Status', 'Ebyte')),
			(108, ('Production SM Negative Total active energy of actual period', 'EEnergy')),
			(120, ('Diagnostic notification queue I', 'EBArrayB(36)')),
			(121, ('Diagnostic notification queue II', 'EBArrayB(36)')),
		])),
		(101, collections.OrderedDict([
			(1, ('Contractual power', 'EPower')),
			(2, ('Available Power', 'EPower')),
			(18, ('Model Type', 'EWord')),
			(22, ('POD (Point of Delivery)', 'EBArray(15)')),
			(24, ('TI Integration time for Load Profile in minutes', 'EByte')),
			(33, ('Power Unit Mode', 'EByte')),
			(45, ('NID SI', 'EBArray(6)')),
		])),
	])

	# Logs info
	LOGS = {
		4: 'Total value of positive active energy (in Wh, 4 bytes) reported for'
			' each time slot Ti, with relative timestamp frozen in the energy'
			' register at Ti. All data in the buffer are (about 10 days of'
			' sampling) sent to the AB starting from the oldest one.',
		7: 'Total value of negative active energy (in Wh, 4 bytes) received by'
			' primary meter reported for each time slot Ti, with relative'
			' timestamp frozen in energy register at Ti. All data in the buffer'
			' are (about 10 days of sampling) sent to the AB starting from the'
			' oldest one.',
		11: 'Only in the prosumer case (Model Type = 0x02), the total value of'
			' negative active energy (in Wh, 4 bytes) received from the'
			' secondary meter reported for each time slot Ti, with relative'
			' timestamp frozen in energy register at Ti. All data in the buffer'
			' are sent to the AB starting from the oldest one.',
	}


	def __init__(self, device):
		self.log = logging.getLogger('ab')
		self.ser = serial.Serial(device, self.DEFBAUD, self.DEFBYTESIZE,
			self.DEFPARITY, self.DEFSTOPBITS, timeout=self.BASETIMEOUT)
		# Receive buffer
		self.inbuf = collections.deque()
		self.enrolled = False
		self.addr = None

	def enroll(self):
		''' Completes the enrollment and address request procedure '''
		self.log.info('Negotiating enrolment')
		req = EnrolmentRequestFrame(0, self.SIADDR, APPID, b'\x01'.ljust(12,b'\x00'), b'\x02'.ljust(16,b'\x00'))
		self.send(req)
		res = self.recv()
		self._expectFrame(res, EnrolmentResponseFrame)
		self._expectAppid(res)
		if res.resultCode != b'\x02':
			raise RuntimeError('Enrolment response not acknowledged, code {}'.format(res.resultCode))
		self.enrolled = True

		self.log.info('Requesting address')
		req = AddressRequestFrame(0, self.SIADDR, APPID)
		self.send(req)
		res = self.recv()
		self._expectFrame(res, AddressResponseFrame)
		self._expectAppid(res)
		self.addr = ord(res.address)
		self.log.info('Received address %s', self.addr)

	def _expectFrame(self, received, expected):
		if isinstance(received, expected):
			return

		if received is None:
			self.log.debug('Inbuf dump: %s', self.inbuf)
		elif isinstance(received, NAckFrame):
			self.log.error('NACK %s: %s', ord(received.resultCode), received.message)
			raise NAckError(ord(received.resultCode), received.message)

		raise RuntimeError('Expected {}, received {}'.format(expected.__name__, received.__class__.__name__))

	def _expectAppid(self, received):
		if received.applicationId != APPID:
			raise RuntimeError('Expected applicationId, received {}'.format(received.applicationId))

	def checkSmLink(self):
		''' Checks link to the smart meter, automatically enroll when needed
		@return True on success
		'''
		if not self.addr:
			self.enroll()

		self.log.info('Pinging Smart Meter')
		req = SmartMeterComLinkCheckRequestFrame(self.addr, self.SIADDR, SmartMeterComLinkCheckRequestFrame.PRIMARY)
		self.send(req)
		res = self.recv()
		self._expectFrame(res, AckFrame)

		return True

	def getDeviceInfo(self):
		''' Requests Smart Info device information
		@return dict
		'''
		if not self.addr:
			self.enroll()

		self.log.info('Requesting device information')
		req = DeviceInfoRequestFrame(self.addr, self.SIADDR, b'\x00')
		self.send(req)
		res = self.recv()
		self._expectFrame(res, DeviceInfoResponseFrame)

		return SiDeviceInfo(
			siRelease = res.siRelease.decode('ascii'),
			siNid = res.siNid.hex(),
			modemSwStackRelease = res.modemSwStackRelease.decode('ascii'),
			modemFwRelease = struct.unpack('>H', res.modemFwRelease)[0],
			siType = ord(res.siType),
		)

	def getTableRow(self, table, row):
		''' Reads a single row from a table
		@see self.TABLES
		@param table int: Table ID 100,101
		@param row int. Row ID 0-255
		@return TableRow or Null if not available
		'''
		if type(table) is not int:
			raise TypeError('table must be int')
		if table not in self.TABLES:
			raise ValueError('table must be ' + ','.join(self.TABLES.keys()))
		if type(row) is not int:
			raise TypeError('row must be int')
		if row < 0 or row > 0xff:
			raise ValueError('row must be 0-255')
		if row not in self.TABLES[table]:
			raise ValueError('row {} is unknown in table {}'.format(table))

		if not self.addr:
			self.enroll()

		section = table - 100

		self.log.info('Requesting row %s from section %s (table %s)', row, section, table)
		req = ReadRequestFrame(self.addr, self.SIADDR, chr(section), chr(row))
		self.send(req)
		res = self.recv()
		try:
			self._expectFrame(res, ReadResponseFrame)
		except NAckError as e:
			if e.code == 4:
				# Row not found
				return None
			raise

		updDate = self.parseEParam(res.updDate, 'Edate')
		updTime = self.parseEParam(res.updTime, 'Etime')
		if updDate and updTime:
			updated = datetime.datetime.combine(updDate, updTime),
		elif updDate is None and updTime is None:
			updated = None
		elif updDate is None:
			updated = updTime
		elif updTime is None:
			updated = updDate

		return TableRow(
			table = ord(res.section) + 100,
			row = ord(res.row),
			value = self.parseEParam(res.value, self.TABLES[table][row][1]),
			updated = updated,
			descr = self.TABLES[table][row][0],
		)

	def getTable(self, table):
		''' Reads all rows from a table
		@see self.TABLES
		@see self.getTableRow
		@param table int: Table ID 100,101
		@return collections.OrderedDict: list of TableRow
		'''
		if type(table) is not int:
			raise TypeError('table must be int')
		if table not in self.TABLES:
			raise ValueError('table must be ' + ','.join(self.TABLES.keys()))

		data = collections.OrderedDict()
		for row in self.TABLES[table].keys():
			data[row] = self.getTableRow(table, row)

		return data

	def parseEParam(self, value, vtype):
		''' Parses a table param into a python one
		@param value bytes: The raw value
		@param vtype str: The type name, case-insensitive
		@return The pythonized value
		'''
		if vtype.lower() in ('Ebyte'.lower(), 'Eshort'.lower()):
			self._checkEParam(value, vtype, 1)
			return ord(value)

		if vtype.lower() in ('Eword'.lower(), 'EPower'.lower()):
			self._checkEParam(value, vtype, 2)
			return struct.unpack('>H', value)[0]

		if vtype.lower() in ('EEnergy'.lower(), 'ESEnergy'.lower()):
			self._checkEParam(value, vtype, 4)
			return struct.unpack('>I', value)[0]

		if vtype.lower() == 'Edate'.lower():
			self._checkEParam(value, vtype, 3)
			d, m, y = value
			if d == m == y == 0:
				return None
			return datetime.date(day=d, month=m, year=y+2000)

		if vtype.lower() == 'Etime'.lower():
			self._checkEParam(value, vtype, 3)
			h, m, s = value
			if h == m == s == 0:
				return None
			return datetime.time(hour=h, minute=m, second=s)

		if vtype.lower() == 'EtimeA'.lower():
			self._checkEParam(value, vtype, 4)
			d, h, m, s = value
			return datetime.timedelta(days=d, hours=h, minutes=m, seconds=s)

		if vtype.lower() == 'EBArrayB'.lower() or vtype.lower().startswith('EBArrayB('.lower()):
			return value

		if vtype.lower() == 'EBArray'.lower() or vtype.lower().startswith('EBArray('.lower()):
			return value.rstrip(b'\x00')

		raise ValueError('Unknown Eparam type {}'.format(vtype))

	def _checkEParam(self, value, vtype, vlen):
		if type(value) is not bytes:
			raise TypeError('Eparam must be bytes')
		if len(value) != vlen:
			raise ValueError('{} must be exactly {} bytes long'.format(vtype, vlen))

	def getLog(self, ltype):
		''' Reads a log (load profile)
		@param ltype int: Log ID 4,7,11
		@return collections.OrderedDict: list of LogRow or None if not available
		'''
		if type(ltype) is not int:
			raise TypeError('ltype must be int')
		if ltype not in self.LOGS:
			raise ValueError('ltype must be ' + ','.join(self.LOGS.keys()))

		if not self.addr:
			self.enroll()

		self.log.info('Requesting log %s', ltype)
		req = LogRequestFrame(self.addr, self.SIADDR, chr(ltype))
		self.send(req)
		res = self.recv()
		try:
			self._expectFrame(res, LogResponseFrame)
		except NAckError as e:
			if e.code == 4:
				# Row not found
				return None
			raise

		y, m, d, h, m = res.firstTime
		firstTime = datetime.datetime(year=y+2000, month=m, day=d, hour=h, minute=m)
		samples = struct.unpack('>H', res.samples)[0]
		ti = ord(res.ti)
		logType = ord(res.logType)
		firstValue = struct.unpack('>I', res.firstValue)[0]

		print (firstTime, samples, ti, logType, firstValue)
		for i in range(samples):
			res = self.recv()
			print(res, res.records)


		return

		updDate = self.parseEParam(res.updDate, 'Edate')
		updTime = self.parseEParam(res.updTime, 'Etime')
		if updDate and updTime:
			updated = datetime.datetime.combine(updDate, updTime),
		elif updDate is None and updTime is None:
			updated = None
		elif updDate is None:
			updated = updTime
		elif updTime is None:
			updated = updDate

		return TableRow(
			table = ord(res.section) + 100,
			row = ord(res.row),
			value = self.parseEParam(res.value, self.TABLES[table][row][1]),
			updated = updated,
			descr = self.TABLES[table][row][0],
		)

	def send(self, frame):
		''' Sends a frame
		@param frame The frame to be sent
		'''
		if not isinstance(frame, Frame):
			raise TypeError('frame must be a Frame object')

		raw = bytes(frame)
		self.ser.write(raw)
		self.ser.flush()
		self.log.debug("=> %s", frame)
		self.log.debug("=> %s", self.formatFrameBytes(raw))
		self.log.debug("=> %s", ' '.join('{:02x}'.format(b) for b in raw))

	def recv(self, timeout=10):
		''' Receive next available packet, blocking up to timeout
		@return next packet if available, or None if no packet was available/discarded
		'''

		timeout = time.time() + timeout
		frame = RecvFrame()

		while time.time() < timeout:
			# Receive all available bytes from the hardware
			while True:
				byte = self.ser.read(1)
				if not len(byte):
					break
				assert len(byte) == 1, byte
				self.inbuf.append(byte)

			# Reads bytes from the buffer until a complete frame is found
			while len(self.inbuf):
				byte = self.inbuf.popleft()
				doneframe = frame.eat(byte)
				if doneframe:
					raw = bytes(frame)
					self.log.debug("<= %s", doneframe)
					self.log.debug("<= %s", self.formatFrameBytes(raw))
					self.log.debug("<= %s", ' '.join('{:02x}'.format(b) for b in raw))
					return doneframe

			time.sleep(self.BASETIMEOUT)

		# Timed out: move bytes back into the receive buffer
		for byte in bytes(frame):
			assert 0 <= byte <= 255
			self.inbuf.append(chr(byte))

		return None

	def formatFrameBytes(self, data):
		''' Returns frame bytes formatted as string '''
		if type(data) is not bytes:
			raise ValueError('data must be bytes')

		ret = '({})'.format(len(data))
		if not len(data):
			return ret

		# Start char
		ret += ' '
		ret +=  'x{:02x}'.format(data[0])
		if len(data) == 1:
			return ret

		# Data len
		ret += ' '
		dlen = data[1]
		ret += '{}'.format(dlen)
		if len(data) == 2:
			return ret

		ret += ' '
		if len(data) != 4 + dlen:
			# Unexpected/invalid data len
			ret += ''.join('x{:02x}'.format(data[x]) for x in range(2, len(data)))
			return ret

		body = data[2:-2]
		csum = data[-2:]

		if len(body) >= 3:
			ret += str(body[0]) + ' ' + str(body[1]) + ' ' + str(body[2]) + ' ' + \
				'({})'.format(len(body)-3) + ''.join('x{:02x}'.format(b) for b in body[3:])
		else:
			ret += '({})'.format(len(body)) + ''.join('x{:02x}'.format(b) for b in body)
		ret += ' ' + 'x{:02x}{:02x}'.format(csum[0], csum[1])
		return ret


if __name__ == '__main__':
	import itertools

	logging.basicConfig(level=logging.DEBUG)

	sic = AB('/dev/ttyACM0')
	#print(sic.checkSmLink())
	#print(sic.getDeviceInfo())
	#for idx, row in sic.getTable(100).items():
	#	print(idx, row)
	#for idx, row in itertools.chain(sic.getTable(100).items(), sic.getTable(101).items()):
	#	if not row:
	#		continue
	#	print('{}: {}'.format(row.descr, row.value))
	print(sic.getTableRow(100, 105))
	print(sic.getLog(4))
