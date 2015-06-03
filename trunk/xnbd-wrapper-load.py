#!/usr/bin/env python


# xNBD - an enhanced Network Block Device program
#
# Copyright (C) 2008-2014 National Institute of Advanced Industrial Science
# and Technology
#
# Author: Sebastian Pipping <sebastian _at_ pipping.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307, USA.

from __future__ import print_function

import json
import sys
import subprocess

try:
    import argparse
except ImportError:
    print('ERROR: Python >=2.7 or python-argparse needed to run', file=sys.stderr)
    sys.exit(1)


class FileFormatViolation(ValueError):
	pass


def require_non_empty(candidate, description):
	if not candidate:
		raise FileFormatViolation('%s "%s" not supported' % (description, candidate))


def run_xnbd_wrapper_ctl(options, argv_one):
	argv = [options.xnbd_wrapper_ctl, ]
	if options.socket:
		argv += ['--socket', options.socket]
	argv += argv_one
	print('# %s' % ' '.join(argv))
	p = subprocess.Popen(argv)
	p.wait()
	if p.returncode:
		print('--> %d' % p.returncode, file=sys.stderr)
	return p.returncode == 0


def process_target_mode(options, local_export_name, image_path):
	argv_one = ['--add-target', local_export_name, image_path]
	return run_xnbd_wrapper_ctl(options, argv_one)


def process_proxy_mode(options, local_export_name,
		remote_host, remote_port, remote_export_name,
		image_path, bitmap_path, control_socket_path):
	argv_one = []
	if remote_export_name:
		argv_one += ['--target-exportname', remote_export_name]
	argv_one += ['--add-proxy', local_export_name, remote_host, remote_port,
			image_path, bitmap_path, control_socket_path]

	return run_xnbd_wrapper_ctl(options, argv_one)


def process_json(options, tree):
	success = True

	version = tree.get('version')
	if version != 2:
		raise FileFormatViolation('Unsupported file format version "%s"' % version)

	images = tree.get('images')
	if images is None:
		return success

	if not isinstance(images, dict):
		raise FileFormatViolation('Images listing is not a dictionary')

	for execute in (False, True):  # First pass with no impact and checking, only
		for local_export_name, details_dict in sorted(images.items()):
			if not local_export_name:
				raise FileFormatViolation('Export name "%s" not supported' % local_export_name)

			mode = details_dict.get('mode')
			if mode not in ('target', 'proxy'):
				raise FileFormatViolation('Image move "%s" not supported' % mode)

			image_path = details_dict.get('image_path')
			require_non_empty(image_path, 'Image path')

			if mode == 'target':
				if execute:
					# Abusing & for non-lazy "and"
					success &= process_target_mode(options, local_export_name, image_path)
			elif mode == 'proxy':
				bitmap_path = details_dict.get('bitmap_path')
				require_non_empty(bitmap_path, 'Image bitmap path')

				control_socket_path = details_dict.get('control_socket_path')
				require_non_empty(control_socket_path, 'Control socket path')

				remote_host = details_dict.get('remote_host')
				require_non_empty(remote_host, 'Remote host')

				remote_port = details_dict.get('remote_port')
				require_non_empty(remote_port, 'Remote port')

				remote_export_name = details_dict.get('remote_export_name')  # may be empty

				if execute:
					# Abusing & for non-lazy "and"
					success &= process_proxy_mode(options, local_export_name,
							remote_host, remote_port, remote_export_name,
							image_path, bitmap_path, control_socket_path)
	return success


def run(options):
	f = open(options.json_filename, 'r')
	content = f.read()
	f.close()

	try:
		tree = json.loads(content)
	except ValueError as e:
		raise FileFormatViolation('Not valid JSON: %s' % e)

	return process_json(options, tree)


def main(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument('--from', dest='json_filename', metavar='FILE',
			default='/var/lib/xnbd/xnbd.state',
			help='Location of JSON state file to load (default: %(default)s)')
	parser.add_argument('--xnbd-wrapper-ctl', metavar='COMMAND', default='xnbd-wrapper-ctl',
			help='Override xnbd-wrapper-ctl command (default: %(default)s)')
	parser.add_argument('--socket', metavar='PATH',
			help='Override xnbd-wrapper control socket path (default left to xnbd-wrapper-ctl)')

	options = parser.parse_args(argv[1:])

	success = False
	try:
		success = run(options)
	except IOError as e:
		print('Error reading database file: %s' % e)
	except OSError as e:
		print('Failed to launch "%s": %s' % (options.xnbd_wrapper_ctl, e))
	except FileFormatViolation as e:
		print('Broken database file: %s' % e)
	except KeyboardInterrupt:
		pass

	return (0 if success else 1)


if __name__ == '__main__':
	sys.exit(main(sys.argv))
