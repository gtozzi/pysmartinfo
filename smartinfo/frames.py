#!/usr/bin/env python3

'''
Unofficial e-distribuzione's Smart Info cummunication library

Frame classes

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


import struct
import logging


class Frame:
	''' A single communication frame'''
	START = 0xf7
	MAXDATALEN = 60 - 3  # 3 = src, dst, attr
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


class AckBaseFrame:
	''' Utility base class for slightly different IN/OUT Ack frames '''
	DATASTRUCT = (('resultCode', 1),)
	# The only possible result code
	POSITIVE = 0x00


class NAckBaseFrame:
	''' Utility base class for slightly different IN/OUT NAck frames '''
	DATASTRUCT = (('resultCode', 1),)

	def _getMessage(self):
		try:
			return self.RESULTS[self.resultCode]
		except KeyError:
			return None


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

class SetLedRequestFrame(OutFrame):
	''' (OUT) Set Led Request '''
	ATTR = 76
	DATASTRUCT = (('status', 1),)

class DiagnosticClearRequestFrame(OutFrame):
	''' (OUT) Diagnostic Clear '''
	ATTR = 96
	# Mode is always zero
	DATASTRUCT = (('mode', 1),)

class ApplAckFrame(AckBaseFrame, OutFrame):
	''' (OUT) Generic positive acnowledgment frame '''
	ATTR = 252

class ApplNAckFrame(NAckBaseFrame, OutFrame):
	''' (OUT) Generic negative acnowledgment frame '''
	ATTR = 254
	# Known result code explanations
	RESULTS = {
		b'\x00': 'Message not correct',
		b'\x01': 'ATTR not valid',
		b'\x02': 'not valid Parameter',
		b'\x03': 'stop sequence',
		b'\x04': 'buffer not available',
	}


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
		''' After inbound init tasks, useful to be overridden in child '''
		pass


class EnrolmentResponseFrame(InFrame):
	''' (IN) A succesfull enrolment response '''
	ATTR = 73
	DATASTRUCT = (('applicationId', 16), ('resultCode', 1))

class AddressResponseFrame(InFrame):
	''' (IN) A succesfull address response '''
	ATTR = 71
	DATASTRUCT = (('applicationId', 16), ('address', 1))

class SiAckFrame(AckBaseFrame, InFrame):
	''' (IN) Generic positive acnowledgment frame '''
	ATTR = 251

	def _afterInInit(self):
		super()._afterInInit()
		if self.resultCode != bytes([self.POSITIVE]):
			raise NotImplementedError('Unexpected ACK result code: {}'.format(self.resultCode))

class SiNAckFrame(NAckBaseFrame, InFrame):
	''' (IN) Generic negative acnowledgment frame '''
	ATTR = 255
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
		self.message = self._getMessage()

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

		self.records = []
		for i in range(0, len(self.recordsData), 9):
			rawRecord = self.recordsData[i:i+9]
			record = (rawRecord[:5], rawRecord[5:])
			self.records.append(record)


class RecvFrame(Frame):
	''' Represents a still unknown frame being received, handles frame reception '''

	KNOWNATTRS = {
		EnrolmentResponseFrame.ATTR: EnrolmentResponseFrame,
		AddressResponseFrame.ATTR: AddressResponseFrame,
		SiAckFrame.ATTR: SiAckFrame,
		SiNAckFrame.ATTR: SiNAckFrame,
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
