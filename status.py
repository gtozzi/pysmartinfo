#!/usr/bin/env python3

'''
Read SmartInfo status
'''


import smartinfo

import datetime
import logging
import json


class StatusJSONEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, smartinfo.ab.SiData):
			return obj.__dict__
		if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
			return obj.isoformat()
		if isinstance(obj, bytes):
			return obj.decode('ascii')
		return super().default(obj)


if __name__ == '__main__':
	#logging.basicConfig(level=logging.DEBUG)

	sic = smartinfo.ab.AB('/dev/ttyACM0')

	data = {
		'success': True,
		'device': sic.getDeviceInfo(),
		'ae_cur_period': sic.getTableRow(100, 6),
		'ne_cur_period': sic.getTableRow(100, 36),
		'rat_cur_period': sic.getTableRow(100, 50),
		'pe_cur_period': sic.getTableRow(100, 108),
		'ae_daily': sic.getTableRow(100, 101),
		'instant_power': sic.getTableRow(100, 105),
		'date': sic.getTableRow(100, 21),
		'time': sic.getTableRow(100, 22),
		'dst': sic.getTableRow(100, 23),
		'tariff': sic.getTableRow(100, 30),
		'contract_power': sic.getTableRow(101, 1),
		'avail_power': sic.getTableRow(101, 2),
		'model': sic.getTableRow(101, 18),
		'pod': sic.getTableRow(101, 22),
		'ti_mins': sic.getTableRow(101, 24),
		'pu_mode': sic.getTableRow(101, 33),
		'ae_log': sic.getLog(4),
		'ne_log': sic.getLog(7),
		'pe_log': sic.getLog(11),
		'diagnostic': sic.getDiagnostic(),
	}

	print(StatusJSONEncoder(indent=4).encode(data))
