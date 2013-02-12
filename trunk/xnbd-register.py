#! /usr/bin/python
# -*- coding: utf-8 -*-

# xnbd-register - a configuration interface to xnbd devices
#
# Copyright (C) 2012 Arno Toell <debian@toell.net>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation
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

CONFIG_FILE = "/etc/xnbd.conf"
XNBD_CLIENT = "xnbd-client"
XNBD_WRAPPER = "xnbd-wrapper"
XNBD_WRAPPER_CTL = "xnbd-wrapper-ctl"
VERBOSE = True

def vprint(msg, **kwargs):
	if (VERBOSE):
		print(msg, **kwargs)

def check_syntax(data):
	if (not isinstance(data, dict)):
		vprint("Invalid syntax in configuration file `%s': Expected a sequence of nbdX and/or server objects")
		sys.exit(1)
	for key in data:
		if (key != "server" and not key.startswith("nbd")):
			vprint("Invalid key: `%s' in configuration file `%s'" % (key, CONFIG_FILE))
			sys.exit(1)

		if (key == "server"):
			server_keys = set(["address", "port", "socket",	"volumes", "logpath"])
			config_keys = set(data[key].keys())
			if (config_keys < server_keys):
				vprint("Incomplete server configuration. Was expecting `address', `port', `socket' and `volumes' in configuration file `%s'"  % CONFIG_FILE)
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
	p = subprocess.Popen(command, stderr = subprocess.STDOUT)
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
	#vprint(start_cmd)
	call(start_cmd, "Starting /dev/%s ... " % (device))

def stop_client(device, data):
	stop_cmd = [XNBD_CLIENT,  '--disconnect', '/dev/%s' % (device)]
	call(stop_cmd, "Stopping /dev/%s ... " % (device))

def start_server(data):
	start_cmd = [XNBD_WRAPPER, "--daemonize", "--logpath", data['logpath'],
		"--laddr", data['address'], "--port", str(data['port']), "--socket", data['socket']]
	#vprint(start_cmd)
	call(start_cmd, "Starting `%s' ..." % (XNBD_WRAPPER))
	for volume in data['volumes']:
		add_volume = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "--add", volume]
		#vprint(add_volume)
		if (os.path.exists(volume)):
			call(add_volume, "Adding `%s' ..." % volume)
		else:
			vprint("%s: Can't access volume" % (volume))

def stop_server(data):
	stop = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "--shutdown"]
	call(stop, "Shutting down all xnbd shares ...")

def print_status(data):
	status = [XNBD_WRAPPER_CTL, "--socket", data['socket'], "-l"]
	#vprint(status)
	call(status, "")


parser = argparse.ArgumentParser(description='xNBD helper to (un)register xNBD devices')
parser.add_argument('-s', '--start', action='store_true', help='mount configured xNBD client connections')
parser.add_argument('-r', '--restart', action='store_true', help='(re-)mount configured xNBD client connections')
parser.add_argument('-t', '--stop', action='store_true', help='umount configured xNBD client connections')
parser.add_argument('-a', '--status', action='store_true', help='umount configured xNBD client connections')
parser.add_argument('--quiet', action='store_true', help='don\'t give verbose output')

args = parser.parse_args()
#print(args)

if(args.quiet):
	VERBOSE = False

try:
	conf_parser = open(CONFIG_FILE, "r")
	read_configuration = ""
	for line in conf_parser.readlines():
		line = re.sub("\#.*$", "", line) # ignore comments
		read_configuration += line

	configuration = json.loads(read_configuration)
except (IOError, OSError) as e:
	vprint("Configuration file not accessible `%s\': %s" % ( CONFIG_FILE, e ) )
except ValueError as e:
	vprint("Syntax error in configuration `%s': %s" % (CONFIG_FILE, e))
	sys.exit(1)

conf_parser.close()
check_syntax(configuration)

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

ordered_items = configuration.keys()
if 'server' in ordered_items:
	ordered_items.remove('server')
	ordered_items = ['server', ] + ordered_items


for instance in ordered_items:
	if (args.stop or args.restart):
		if (instance == 'server'):
			stop_server(configuration[instance])
		else:
			stop_client(instance, configuration[instance])
	if (args.start or args.restart):
		if (instance == 'server'):
			start_server(configuration[instance])
		else:
			start_client(instance, configuration[instance])

sys.exit(0)
