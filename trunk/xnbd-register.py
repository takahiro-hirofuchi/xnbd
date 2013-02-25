#! /usr/bin/python
# -*- coding: utf-8 -*-

# xnbd-register - a configuration interface to xnbd devices
#
# Copyright (C) 2012 Arno Toell <arno@debian.org>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


from __future__ import print_function

import argparse
import sys
import subprocess
import json
import re
import os.path
import types

XNBD_CLIENT = "xnbd-client"
XNBD_WRAPPER = "xnbd-wrapper"
XNBD_WRAPPER_CTL = "xnbd-wrapper-ctl"
VERBOSE = True

def vprint(msg, **kwargs):
	if (VERBOSE):
		print(msg, **kwargs)

def check_syntax(data, config_file):
	if (not isinstance(data, dict)):
		vprint("Invalid syntax in configuration file `%s': Expected a sequence of nbdX and/or server objects")
		sys.exit(1)
	for key in data:
		if (key != "server" and not key.startswith("nbd")):
			vprint("Invalid key: `%s' in configuration file `%s'" % (key, config_file))
			sys.exit(1)

		if (key == "server"):
			server_keys = set(["address", "port", "socket",	"volumes", "logpath"])
			config_keys = set(data[key].keys())
			if (config_keys < server_keys):
				vprint("Incomplete server configuration. Was expecting `address', `port', `socket' and `volumes' in configuration file `%s'"  % config_file)
				sys.exit(1)

			ukeys = config_keys - server_keys
			if (ukeys):
				vprint("WARNING: Unknown server option(s): %s\n" % reduce(lambda x,y: x + y,  ["%s"% (x) for x in ukeys]))
			continue

		elif (key.startswith("nbd")):
			if (not re.match("nbd\d+", key)):
				vprint("Invalid NBD device: %s" % key)
				sys.exit(1)
			if (not "host" in data[key] or not "port" in data[key]):
				vprint("Incomplete NBD configuration. Was expecting `host' and `port' for NBD device `%s'" % (key))
				sys.exit(1)
			continue

		else:
			vprint("Unknown configuration object: `%s'" % key)
			sys.exit(1)


def call(command, description):
	vprint(description, end='')
	try:
		p = subprocess.Popen(command, stderr = subprocess.STDOUT)
	except OSError:
		vprint("failed")
		return 127

	p.wait()
	if (p.returncode != 0):
		vprint("failed")
		sys.exit(p.returncode)
	else:
		vprint("ok")
	return p.returncode

def start_client(device, data):
	start_cmd = [XNBD_CLIENT, '/dev/%s' % (device), '--connect']
	if ('name' in data):
		start_cmd.append("--exportname")
		start_cmd.append(data['name'])

	start_cmd.append(data['host'])
	start_cmd.append(str(data['port']))
	call(start_cmd, "Starting /dev/%s ... " % (device))

def stop_client(device, data):
	stop_cmd = [XNBD_CLIENT,  '--disconnect', '/dev/%s' % (device)]
	call(stop_cmd, "Stopping /dev/%s ... " % (device))

def start_server(data):
	start_cmd = [XNBD_WRAPPER, "--daemonize", "--logpath", data['logpath'],
		"--laddr", data['address'], "--port", str(data['port']), "--socket", data['socket']]
	if call(start_cmd, "Starting `%s' ..." % (XNBD_WRAPPER)):
		sys.exit(1)

	if isinstance(data['volumes'], types.ListType):
		# List data, format of 0.1.0-pre*
		exportname_volume_tuple_list = [(path, path) for path in data['volumes']]
	else:
		# Dict data, format of >=0.2.0
		exportname_volume_tuple_list = list(data['volumes'].items())

	for exportname, volume in exportname_volume_tuple_list:
		add_volume = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "--add-target", exportname, volume]
		if (os.path.exists(volume)):
			call(add_volume, "Adding `%s' ..." % volume)
		else:
			vprint("%s: Can't access volume" % (volume))

def stop_server(data):
	stop = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "--shutdown"]
	call(stop, "Shutting down all xnbd shares ...")

def print_status(data):
	status = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "-l"]
	call(status, "")


parser = argparse.ArgumentParser(description='xNBD helper to (un)register xNBD devices')
parser.add_argument('-s', '--start', action='store_true', help='mount configured xNBD client connections')
parser.add_argument('-r', '--restart', action='store_true', help='(re-)mount configured xNBD client connections')
parser.add_argument('-t', '--stop', action='store_true', help='umount configured xNBD client connections')
parser.add_argument('-a', '--status', action='store_true', help='umount configured xNBD client connections')
parser.add_argument('--config', dest='config_file', default='/etc/xnbd.conf', help='config file to use (default: /etc/xnbd.conf)')
parser.add_argument('--quiet', action='store_true', help='don\'t give verbose output')

args = parser.parse_args()

if(args.quiet):
	VERBOSE = False

try:
	conf_parser = open(args.config_file, "r")
	read_configuration = ""
	for line in conf_parser.readlines():
		line = re.sub("\#.*$", "", line) # ignore comments
		read_configuration += line

	configuration = json.loads(read_configuration)
except (IOError, OSError) as e:
	vprint("Configuration file not accessible `%s\': %s" % ( args.config_file, e ) )
	sys.exit(1)
except ValueError as e:
	vprint("Syntax error in configuration `%s': %s" % (args.config_file, e))
	sys.exit(1)

conf_parser.close()
check_syntax(configuration, args.config_file)

if ( not len(configuration) ):
	vprint("WARNING: Not starting anything")
	sys.exit(2)


if (args.status):
	if (not 'server' in configuration):
		vprint("WARNING: No known server socket")
		sys.exit(2)
	print_status(configuration['server'])
	sys.exit(0)

if (not args.stop and not args.restart and not args.start):
	vprint("%s: One action is required" % sys.argv[0])
	sys.exit(1)

client_device_names = [k for k in configuration.keys() if k != 'server']
wrapper_configured = 'server' in configuration

if (args.stop or args.restart):
	# Stop clients first, they may be using our own wrapper
	for instance in client_device_names:
		stop_client(instance, configuration[instance])

	if wrapper_configured:
		stop_server(configuration['server'])

if (args.start or args.restart):
	# Start wrapper frist, it may be used our own clients
	if wrapper_configured:
		start_server(configuration['server'])

	for instance in client_device_names:
		start_client(instance, configuration[instance])

sys.exit(0)
