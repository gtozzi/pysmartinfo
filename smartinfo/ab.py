#!/usr/bin/env python3

'''
Unofficial e-distribuzione's Smart Info cummunication library

Client (Additional Block) implementation classes

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

from . import frames


NAME = 'pysmartinfo'
VERSION = '0.1'
# The only authorized ApplicationID, as stated in spec 4.2.1
APPID = b'PCMC000000XXXXXX'

class SiData:
	''' Empty base common class '''
	pass

@attr.s(frozen=True)
class SiDeviceInfo(SiData):
	''' Holds Smart Info device info data '''
	siRelease = attr.ib()
	siNid = attr.ib()
	modemSwStackRelease = attr.ib()
	modemFwRelease = attr.ib()
	siType = attr.ib()

@attr.s(frozen=True)
class TableRow(SiData):
	''' Holds table row data '''
	table = attr.ib()
	row = attr.ib()
	value = attr.ib()
	updated = attr.ib()
	descr = attr.ib()

@attr.s(frozen=True)
class Log(SiData):
	''' Holds the log headers and samples (rows) '''
	firstTime = attr.ib()
	samplesCnt = attr.ib()
	ti = attr.ib()
	logType = attr.ib()
	firstValue = attr.ib()
	samples = attr.ib()

@attr.s(frozen=True)
class LogSample(SiData):
	''' Holds a single log sample '''
	timestamp = attr.ib()
	value = attr.ib()

@attr.s(frozen=True)
class Notification(SiData):
	''' Holds a notification '''
	type = attr.ib()
	typeName = attr.ib()
	typeDescr = attr.ib()
	code = attr.ib()
	name = attr.ib()
	timestamp = attr.ib()
	extra = attr.ib()


class NAckError(RuntimeError):
	''' Raised when a NACK is received '''

	def __init__(self, code, message):
		self.code = code
		self.message = message
		super().__init__('{}: {}'.format(self.code, self.message))


class AB:
	''' SmartInfo serial Additional Block (client) implementation

	@warning Packets with wrong checksum are ignored by SI, data is big-endian
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

	# Notification types code: (name, descr)
	NOTIFICATION_TYPES = {
		1: ('INFO', 'Informative'),
		2: ('ERROR', 'Internal operating error'),
		3: ('WARNING', 'Warning and degradation signalling'),
		4: ('FATAL', 'No operation'),
		5: ('PW_LINK', 'Power Line Communication Error'),
		6: ('HOST_LINK', 'Host Communication Error'),
	}

	# Notification descriptions (type, code): (name, timestamp)
	NOTIFICATIONS = {
		(1,  1): ('NOTIFICATION_BOOT', True),
		(1,  2): ('NOTIFICATION_DIAGNOSTIC_CLEARED', True),
		(1,  3): ('NOTIFICATION_DIAGNOSTIC_AUTOCLEARED', True),
		(2,  1): ('NOTIFICATION_CE_NOT_ASSIGNED', True),
		(2,  2): ('NOTIFICATION_CE_NOT_ASSIGNED_RESUMED', True),
		(2,  3): ('NOTIFICATION_AVAILABLE_POWER_NOT_ASSIGNED', True),
		(2,  4): ('NOTIFICATION_AVAILABLE_POWER_NOT_ASSIGNED_RESUMED', True),
		(2,  5): ('NOTIFICATION_TAB_CODE_PRIMARY_NO_MAPPING', False),
		(2,  6): ('NOTIFICATION_TAB_CODE_PRIMARY_NO_MAPPING_RESUMED', True),
		(2,  7): ('NOTIFICATION_TAB_CODE_SECONDARY_NO_MAPPING', False),
		(2,  8): ('NOTIFICATION_TAB_CODE_SECONDARY_NO_MAPPING_RESUMED', True),
		(2,  9): ('NOTIFICATION_TAB_CODE_PRODUCTION_NO_MAPPING', False),
		(2, 10): ('NOTIFICATION_TAB_CODE_PRODUCTION_NO_MAPPING_RESUMED', True),
		(2, 11): ('NOTIFICATION_CE_PRIMARY_TABLE_NOT_ASSIGNED', True),
		(2, 12): ('NOTIFICATION_CE_PRIMARY_TABLE_NOT_ASSIGNED_RESUMED', True),
		(3,  1): ('NOTIFICATION_BATTERY_LOW', True),
		(3,  2): ('NOTIFICATION_BATTERY_LOW_RESUMED', True),
		(3,  3): ('NOTIFICATION_NO_PERIODIC_DATA_FROM_PRIMARY_CE', True),
		(3,  4): ('NOTIFICATION_NO_PERIODIC_DATA_FROM_PRIMARY_CE_RESUMED', True),
		(3,  5): ('NOTIFICATION_NO_PERIODIC_DATA_FROM_SECONDARY_CE', True),
		(3,  6): ('NOTIFICATION_NO_PERIODIC_DATA_FROM_SECONDARY_CE_RESUMED', True),
		(3,  7): ('NOTIFICATION_UNRESPONSIVE_PRIMARY_TABLE', True),
		(3,  8): ('NOTIFICATION_UNRESPONSIVE_PRIMARY_TABLE_RESUMED', True),
		(4,  1): ('NOTIFICATION_MODEM_COMMUNICATION_KO', True),
		(4,  2): ('NOTIFICATION_MODEM_COMMUNICATION_KO_RESUMED', True),
		(4,  3): ('NOTIFICATION_ZERO_CROSSING_FAULT', True),
		(4,  4): ('NOTIFICATION_ZERO_CROSSING_FAULT_RESUMED', True),
		(5,  1): ('NOTIFICATION_CE_TABLE_SIZE_MISMATCH', False),
		(5,  2): ('NOTIFICATION_CE_TABLE_SIZE_MISMATCH_RESUMED', False),
		(5,  3): ('NOTIFICATION_CE_TABLE_INVALID_DATA', False),
		(5,  4): ('NOTIFICATION_CE_TABLE_INVALID_DATA_RESUMED', False),
		(5,  5): ('NOTIFICATION_INCOMING_ACTIVE_ENERGY_NOT_VALID', True),
		(5,  6): ('NOTIFICATION_INCOMING_ACTIVE_ENERGY_NOT_VALID_RESUMED', True),
		(5,  7): ('NOTIFICATION_INCOMING_NEGATIVE_ENERGY_NOT_VALID', True),
		(5,  8): ('NOTIFICATION_INCOMING_NEGATIVE_ENERGY_NOT_VALID_RESUMED', True),
		(5,  9): ('NOTIFICATION_INCOMING_PRODUCTION_ENERGY_NOT_VALID', True),
		(5, 10): ('NOTIFICATION_INCOMING_PRODUCTION_ENERGY_NOT_VALID_RESUMED', True),
		(6,  1): ('NOTIFICATION_CHECKSUM_ERROR', True),
		(6,  2): ('NOTIFICATION_CHECKSUM_ERROR_RESUMED', True),
		(6,  3): ('NOTIFICATION_TIMING_ERROR', True),
		(6,  4): ('NOTIFICATION_TIMING_ERROR_RESUMED', True),
		(6,  5): ('NOTIFICATION_STX_ERROR', True),
		(6,  6): ('NOTIFICATION_STX_ERROR_RESUMED', True),
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
		req = frames.EnrolmentRequestFrame(0, self.SIADDR, APPID, b'\x01'.ljust(12,b'\x00'), b'\x02'.ljust(16,b'\x00'))
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.EnrolmentResponseFrame)
		self._expectAppid(res)
		if res.resultCode != b'\x02':
			raise RuntimeError('Enrolment response not acknowledged, code {}'.format(res.resultCode))
		self.enrolled = True

		self.log.info('Requesting address')
		req = frames.AddressRequestFrame(0, self.SIADDR, APPID)
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.AddressResponseFrame)
		self._expectAppid(res)
		self.addr = ord(res.address)
		self.log.info('Received address %s', self.addr)

	def _expectFrame(self, received, expected):
		if isinstance(received, expected):
			return

		if received is None:
			self.log.debug('Inbuf dump: %s', self.inbuf)
		elif isinstance(received, frames.SiNAckFrame):
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
		req = frames.SmartMeterComLinkCheckRequestFrame(self.addr, self.SIADDR, frames.SmartMeterComLinkCheckRequestFrame.PRIMARY)
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.SiAckFrame)

		return True

	def getDeviceInfo(self):
		''' Requests Smart Info device information
		@return dict
		'''
		if not self.addr:
			self.enroll()

		self.log.info('Requesting device information')
		req = frames.DeviceInfoRequestFrame(self.addr, self.SIADDR, b'\x00')
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.DeviceInfoResponseFrame)

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
		req = frames.ReadRequestFrame(self.addr, self.SIADDR, chr(section), chr(row))
		self.send(req)
		res = self.recv()
		try:
			self._expectFrame(res, frames.ReadResponseFrame)
		except NAckError as e:
			if e.code == 4:
				# Row not found
				return None
			raise

		updDate = self.parseEParam(res.updDate, 'Edate')
		updTime = self.parseEParam(res.updTime, 'Etime')
		if updDate and updTime:
			updated = datetime.datetime.combine(updDate, updTime)
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

	def getDiagnostic(self):
		''' Reads diagnostic info from table 100 rows 120 and 121
		@return Diagnostic info
		'''
		row120 = self.getTableRow(100, 120)
		row121 = self.getTableRow(100, 121)

		diag = row120.value + row121.value

		notifications = []
		for idx in range(0, 6*12, 6):
			raw = diag[idx:idx+6]
			ntype, code, tsOrExtra = struct.unpack('>BBI', raw)

			if ntype == 0:
				assert code == 0 and tsOrExtra == 0, 'Non empty zero-notification'
				continue

			if ntype in self.NOTIFICATION_TYPES:
				typeName, typeDescr = self.NOTIFICATION_TYPES[ntype]
			else:
				typeName = typeDescr = None

			if (ntype, code) in self.NOTIFICATIONS:
				name, hasts = self.NOTIFICATIONS[(ntype, code)]
			else:
				name = hasts = None

			notifications.append(Notification(
				type = ntype,
				typeName = typeName,
				typeDescr = typeDescr,
				code = code,
				name = name,
				timestamp = datetime.datetime.utcfromtimestamp(tsOrExtra) if hasts else None,
				extra = tsOrExtra if not hasts else None,
			))

		return notifications

	def clearDiagnostic(self):
		''' Clears diagnostic info (table 100 rows 120 and 121)
		@return True on success
		'''
		if not self.addr:
			self.enroll()

		self.log.info('Requesting diagnostic clear')
		req = frames.DiagnosticClearRequestFrame(self.addr, self.SIADDR, b'\x00')
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.SiAckFrame)

		return True

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
		@return Log or None if not available
		'''
		if type(ltype) is not int:
			raise TypeError('ltype must be int')
		if ltype not in self.LOGS:
			raise ValueError('ltype must be ' + ','.join(self.LOGS.keys()))

		if not self.addr:
			self.enroll()

		self.log.info('Requesting log %s', ltype)
		req = frames.LogRequestFrame(self.addr, self.SIADDR, chr(ltype))
		self.send(req)
		res = self.recv()
		try:
			self._expectFrame(res, frames.LogResponseFrame)
		except NAckError as e:
			if e.code == 4:
				# Row not found
				return None
			raise

		y, m, d, h, n = res.firstTime
		log = Log(
			firstTime = datetime.datetime(year=y+2000, month=m, day=d, hour=h, minute=n),
			samplesCnt = struct.unpack('>H', res.samples)[0],
			ti = ord(res.ti),
			logType = ord(res.logType),
			firstValue = struct.unpack('>I', res.firstValue)[0],
			samples = [],
		)

		# Just if samplesCnt + while True in one row
		while log.samplesCnt:
			# Receive next block, will contain up to 6 samples
			block = self.recv()
			if block is None:
				break

			# Acknowledge it
			ack = frames.ApplAckFrame(self.addr, self.SIADDR, frames.ApplAckFrame.POSITIVE)
			self.send(ack)

			assert block.logType == res.logType
			bid = ord(block.block)
			blocks = ord(block.blocks)
			self.log.debug('Block %s/%s', bid, blocks)
			for ts, sample in block.records:
				y, m, d, h, n = ts
				sample = LogSample(
					timestamp = datetime.datetime(year=y+2000, month=m, day=d, hour=h, minute=n),
					value = struct.unpack('>I', sample)[0],
				)
				self.log.debug('Sample: %s', sample)
				log.samples.append(sample)

			if bid == blocks:
				# Last block
				break

		assert len(log.samples) == log.samplesCnt
		return log

	def setLed(self, on, color='green', blink=False):
		''' Sets SI led status
		@param on: led on/off status
		@param color: 'yellow' or 'green' (ignored on off)
		@param blink: 'fast', 'slow' or False
		@return True on success
		'''
		if type(on) is not bool:
			raise TypeError('on must be bool')
		if type(color) is not str:
			raise TypeError('color must be str')
		if type(blink) not in (str, bool):
			raise TypeError('blink must be str or bool')
		if color not in ('green', 'yellow'):
			raise ValueError('color must be yellow or green')
		if blink is not False and blink not in ('fast', 'slow'):
			raise ValueError('blink must be False, slow or fast')

		if not self.addr:
			self.enroll()

		# 0: OFF
		# 1: Yellow blinking slow
		# 2: Yellow blinking fast
		# 3: Green blinking slow
		# 4: Green blinking fast
		# 5: Green ON
		# 6: Yellow ON
		if not on:
			status = 0
		elif color == 'yellow' and blink == 'slow':
			status = 1
		elif color == 'yellow' and blink == 'fast':
			status = 2
		elif color == 'yellow' and blink is False:
			status = 6
		elif color == 'green' and blink == 'slow':
			status = 3
		elif color == 'green' and blink == 'fast':
			status = 4
		elif color == 'green' and blink is False:
			status = 5
		else:
			raise NotImplementedError()

		self.log.info('Setting SI Led status %s', status)
		req = frames.SetLedRequestFrame(self.addr, self.SIADDR, status)
		self.send(req)
		res = self.recv()
		self._expectFrame(res, frames.SiAckFrame)

		return True

	def send(self, frame):
		''' Sends a frame
		@param frame The frame to be sent
		'''
		if not isinstance(frame, frames.Frame):
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
		frame = frames.RecvFrame()

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
