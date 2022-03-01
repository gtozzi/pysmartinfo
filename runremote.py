#!/usr/bin/env python3

'''
Runs smartinfo.py remotely via SSH, useful for developing purposes
'''


import os
import argparse
import subprocess


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Runs smartinfo.py remotely via ssh')
	parser.add_argument('dest', help='remote user and host')
	parser.add_argument('--destpath', default='/tmp', help='destination path')

	args = parser.parse_args()
	root = os.path.dirname(os.path.abspath(__file__))

	cmd = ('rsync', '-rE', '--progress', '--exclude=__pycache__', '--exclude=.git',
		root, args.dest + ':' + args.destpath)
	subprocess.run(cmd)

	cmd = ('ssh', args.dest, args.destpath + '/' + os.path.basename(root) + '/status.py')
	subprocess.run(cmd)
