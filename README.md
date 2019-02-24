# pysmartinfo
Unofficial e-distribuzione's Smart Info python cummunication library

Example usage:
```python
	import smartinfo
	import logging
	import itertools

	# Optional: initialize logging and
	# set debug log level to see a lot of spam, raw packets, etc…
	logging.basicConfig(level=logging.DEBUG)

	# Instantiate the Additional Block (client) over the USB serial connection
	ab = smartinfo.ab.AB('/dev/ttyACM0')

	# Perform a "Ping" test
	print(sic.checkSmLink())

	# prints:
	# True

	# Retrieve info about your Smart Info device
	print(sic.getDeviceInfo())

	# prints:
	# SiDeviceInfo(siRelease='SIMSTD1C', siNid='xxxxxxxxxxxx',
	# modemSwStackRelease='STstek11', modemFwRelease=171, siType=3)

	# Read rows from all tables (100 and 101)
	for idx, row in itertools.chain(sic.getTable(100).items(), sic.getTable(101).items()):
		if not row:
			# Some rows may not be present and will return None
			continue
		print('{}: {}'.format(row.descr, row.value))

	# prints:
	# E(t) Total active energy of actual period: 2000000
	# DATE: 2019-02-12
	# TIME: 07:45:21
	# Daylight disabled/enabled: 0
	# Tall Time of alarm: 3:12:02
	# TypAl Type of Alarm: 0
	# Tariff code: 10
	# E-(t) Total negative active energy of actual period: 100000
	# Total daily active energy current date: 3000
	# Instant Power (Average in Time Tx, 1 second) - PTx: 500
	# Diagnostic notification queue I: b'<binary data>'
	# Diagnostic notification queue II: b'<binary data>'
	# Contractual power: 1000
	# Available Power: 1100
	# Model Type: 0
	# POD (Point of Delivery): b'XXXXXXXXXXXXXX'
	# TI Integration time for Load Profile in minutes: 15
	# Power Unit Mode: 0
	# NID SI: b'<binary id>'

	# Reads the total value of positive active energy log
	log = sic.getLog(4)
	for sample in log.samples:
		print(str(sample.timestamp), sample.value)

	# prints:
	# 2019-02-08 11:05:00 2000000
	# 2019-02-08 11:44:00 2000200
	# 2019-02-08 11:54:00 2000400
	# …
	# 2019-02-12 07:37:00 2002000

	# Sets Smart Info led as Yellow, blinking fast
	sic.setLed(True, 'yellow', 'fast')
```
