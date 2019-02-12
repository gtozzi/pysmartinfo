#!/usr/bin/env python3

'''
Runs some tests
'''


import smartinfo
import logging
import itertools


if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)

	sic = smartinfo.ab.AB('/dev/ttyACM0')
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
