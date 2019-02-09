#!/usr/bin/env python3

'''
e-distribuzione Smart Info cummunication library

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

		self.parseDataStruct()
		self.afterInInit()

	def parseDataStruct(self):
		datalen = 0
		for name, length in self.DATASTRUCT:
			datalen += length
		if len(self.data) != datalen:
			raise ValueError('Data len mismatch, expected {}, got {}'.format(datalen, len(self.data)))

		idx = 0
		for name, length in self.DATASTRUCT:
			value = self.data[idx:idx+length]
			setattr(self, name, value)
			idx += length

	def afterInInit(self):
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

	def afterInInit(self):
		super().afterInInit()
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

	def afterInInit(self):
		super().afterInInit()
		if self.resultCode != self.POSITIVE:
			raise NotImplementedError('Unexpected ACK result code: {}'.format(self.resultCode))

class DeviceInfoResponseFrame(InFrame):
	''' (IN) A succesfull device information response '''
	ATTR = 91
	DATASTRUCT = (('infoSetCode', 1), ('siRelease', 8), ('siNid', 6),
		('modemSwStackRelease', 8), ('modemFwRelease', 2), ('siType', 1))


class RecvFrame(Frame):
	''' Represents a still unknown frame being received, handles frame reception '''

	KNOWNATTRS = {
		EnrolmentResponseFrame.ATTR: EnrolmentResponseFrame,
		AddressResponseFrame.ATTR: AddressResponseFrame,
		AckFrame.ATTR: AckFrame,
		NAckFrame.ATTR: NAckFrame,
		DeviceInfoResponseFrame.ATTR: DeviceInfoResponseFrame,
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

	def eat(self, byte):
		''' Eats next byte for the packet
		@param byte bytes: Single byte to eat
		@return A Frame object when packet is complete
		'''
		byte = self._bytesParam('byte', byte, 1, False)

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
					return self.KNOWNATTRS[ord(self.attr)](self)
				return self
			return None

		if self._status == 'done':
			raise RuntimeError('Packet is complete, cannot eat more bytes')

		raise RuntimeError('Internal error: unknown status {}'.format(self._status))


@attr.s(frozen=True)
class SiDeviceInfo:
	''' Holds Smart Info device info data '''
	siRelease = attr.ib()
	siNid = attr.ib()
	modemSwStackRelease = attr.ib()
	modemFwRelease = attr.ib()
	siType = attr.ib()


class Client:
	''' SmartInfo serial client implementation

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

	def __init__(self, device):
		self.log = logging.getLogger('siclient')
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
		if not isinstance(received, expected):
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

		return self.inbuf

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
	import logging
	logging.basicConfig(level=logging.DEBUG)

	sic = Client('/dev/ttyACM0')
	print(sic.checkSmLink())
	print(sic.getDeviceInfo())
