#!/usr/bin/env python3

'''
Runs some tests
'''


import smartinfo
import logging
import itertools
import time


if __name__ == '__main__':
	#logging.basicConfig(level=logging.DEBUG)

	sic = smartinfo.ab.AB('/dev/ttyACM0')

	print(sic.checkSmLink())
	print(sic.getDeviceInfo())

	#for idx, row in sic.getTable(100).items():
	#	print(idx, row)

	#for idx, row in itertools.chain(sic.getTable(100).items(), sic.getTable(101).items()):
	#	if not row:
	#		continue
	#	print('{}: {}'.format(row.descr, row.value))

	#print(sic.getTableRow(100, 105))

	#log = sic.getLog(4)
	#for sample in log.samples:
	#	print(str(sample.timestamp), sample.value)

	#sic.setLed(False)

	#sic.clearDiagnostic()

	#for notification in sic.getDiagnostic():
	#	print(notification)

	while(True):
		print(sic.getTableRow(100, 105), flush=True)
		time.sleep(1)
