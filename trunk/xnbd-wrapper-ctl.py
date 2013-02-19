#!/usr/bin/env python


# xNBD - an enhanced Network Block Device program
# 
# Copyright (C) 2008-2013 National Institute of Advanced Industrial Science
# and Technology
# 
# Author: Takahiro Hirofuchi <t.hirofuchi _at_ aist.go.jp>
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

import socket
import re
import sys
import os
import errno
import urllib
import types

try:
    import argparse
except ImportError:
    print('ERROR: Python >=2.7 or python-argparse needed to run', file=sys.stderr)
    sys.exit(1)


def prog(argv_zero):
    return os.path.basename(argv_zero)


def percent_encode(thing):
    if isinstance(thing, (types.TupleType, types.ListType)):
        return [percent_encode(e) for e in thing]
    return urllib.quote(str(thing))


class XNBDWrapperCtl:

    pattern = ".*\(xnbd\) "

    def __init__(self, sockpath):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sockpath)
        self.sock.recv(4096)  # drop unnecessary message

    def _read_response(self):
        buf = ""
        while True:
            try:
                buf += self.sock.recv(4096)
            except:
                sys.stderr.write(sys.exc_info()[1])
                break

            if re.search(self.pattern, buf, re.S):
                break

        return re.sub("\(xnbd\) ", "", buf)

    def send_cmd(self, cmd):
        self.sock.send(cmd + "\n")
        return self._read_response()

    def __del__(self):
    	try:
        	self.sock.send("quit")
        	#self.file_obj.close()
        	self.sock.close()
	except:
		# We don't care about sockets being closed while closing sockets ...
		pass


class FixedHelpFormatter(argparse.HelpFormatter):
    def _format_args(self, action, default_metavar):
        if action.nargs > 1:
            return ' '.join(action.metavar[:action.nargs])
        return super(FixedHelpFormatter, self)._format_args(action, default_metavar)


def parse_command_line(argv):
    parser = argparse.ArgumentParser(formatter_class=FixedHelpFormatter, usage="""
  %(prog)s [-s SOCKPATH] --list
  %(prog)s [-s SOCKPATH] --add-target LOCAL_EXPORTNAME FILE
  %(prog)s [-s SOCKPATH] [--target-exportname NAME] --add-proxy LOCAL_EXPORTNAME REMOTE_HOST REMOTE_PORT CACHE_IMAGE BITMAP_IMAGE CONTROL_SOCKET_PATH
  %(prog)s [-s SOCKPATH] --remove-by-file FILE
  %(prog)s [-s SOCKPATH] --remove-by-exportname NAME
  %(prog)s [-s SOCKPATH] --shutdown

  %(prog)s [-s SOCKPATH] --bgctl-query LOCAL_EXPORTNAME
  %(prog)s [-s SOCKPATH] --bgctl-switch LOCAL_EXPORTNAME
  %(prog)s [-s SOCKPATH] --bgctl-cache-all LOCAL_EXPORTNAME
  %(prog)s [-s SOCKPATH] [--target-exportname NAME] --bgctl-reconnect LOCAL_EXPORTNAME REMOTE_HOST REMOTE_PORT
""")

    operations = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument("-s", "--socket",
                        dest="sockpath", default="/var/run/xnbd-wrapper.ctl",
                        help="specify the socket file path of xnbd-wrapper.")

    operations.add_argument("--list", "-l", action='store_true',
                        help="list registered disk images.")
    operations.add_argument("--add-target", metavar=['LOCAL_EXPORTNAME', 'FILE'], nargs=2,
                        help="add a disk image file to the export list.")
    operations.add_argument("--add-proxy", metavar=['LOCAL_EXPORTNAME', 'REMOTE_HOST', 'REMOTE_PORT', 'CACHE_IMAGE', 'BITMAP_IMAGE', 'CONTROL_SOCKET_PATH'], nargs=6,
                        help="add a disk image file to the export list.")
    operations.add_argument("--remove-by-file", metavar='FILE',
                        help="remove a disk image file from the list.")
    operations.add_argument("--remove-by-exportname", metavar='NAME',
                        help="remove a disk image file from the list.")
    operations.add_argument("--shutdown", "-d", action='store_true',
                        help="remove all disk images from the xnbd-wrapper instance and stop it afterwards.")

    operations.add_argument("--bgctl-query", metavar='LOCAL_EXPORTNAME',
                        help="query current status of the proxy mode.")
    operations.add_argument("--bgctl-switch", metavar='LOCAL_EXPORTNAME',
                        help="cache all blocks.")
    operations.add_argument("--bgctl-cache-all", metavar='LOCAL_EXPORTNAME',
                        help="cache all blocks with the background connection.")
    operations.add_argument("--bgctl-reconnect", metavar=['LOCAL_EXPORTNAME', 'REMOTE_HOST', 'REMOTE_PORT'], nargs=3,
                        help="reconnect the forwarding session.")

    parser.add_argument("--target-exportname", metavar='NAME',
                        help="set the export name to request from a xnbd-wrapper target (used with --add-proxy).")

    deprecated_operations = parser.add_argument_group('deprecated arguments')

    deprecated_operations.add_argument("--add", "-a", metavar='FILE',
                        help="alias to --add-target, deprecated")
    deprecated_operations.add_argument("--remove", "-r", metavar='INDEX', type=int,
                        help="remove a disk image file from the list, deprecated")

    options = parser.parse_args(argv[1:])

    if options.target_exportname and not any([options.add_proxy, options.bgctl_reconnect]):
        print('%s: error: Argument --target-exportname is only supported in combination with --add-proxy and --bgctl-reconnect.' % prog(argv[0]), file=sys.stderr)
        sys.exit(1)

    return options


def compose_command(options, argv):
    # Zero argument commands
    zero_arg_commands = (
        (options.list, 'list'),
        (options.shutdown, 'shutdown'),
    )
    for dest, line in zero_arg_commands:
        if dest:
            return line

    single_arg_exportname_commands = (
        (options.bgctl_query, 'bgctl-query'),
        (options.bgctl_switch, 'bgctl-switch'),
        (options.bgctl_cache_all, 'bgctl-cache-all'),
    )
    for dest, command in single_arg_exportname_commands:
        if dest:
            encoded_arg = urllib.quote(str(dest))
            return '%s %s' % (command, encoded_arg)

    # Single argument commands
    single_arg_commands = (
        (options.remove, 'del'),  # deprecated
        (options.remove_by_file, 'del-file'),
        (options.remove_by_exportname, 'del-exportname'),
    )
    for dest, command_name, in single_arg_commands:
        if dest:
            return '%s %s' % (command_name, percent_encode(dest))

    # More complex commands
    if options.add_proxy:
        args = []
        args.extend(options.add_proxy)
        if options.target_exportname:
            args.append(options.target_exportname)

        return 'add-proxy %s' % ' '.join(percent_encode(args))
    elif options.add:  # deprecated
        args = []
        args.append(options.add)  # local exportname
        args.append(options.add)  # image name

        return 'add-target %s' % ' '.join(percent_encode(args))
    elif options.add_target:
        args = []
        args.extend(options.add_target)

        return 'add-target %s' % ' '.join(percent_encode(args))
    elif options.bgctl_reconnect:
        args = []
        args.extend(options.bgctl_reconnect)
        if options.target_exportname:
            args.append(options.target_exportname)

        return 'bgctl-reconnect %s' % ' '.join(percent_encode(args))

    assert False, 'Internal error, no command used'


if __name__ =='__main__':
    opts = parse_command_line(sys.argv)

    try:
        ctl = XNBDWrapperCtl(opts.sockpath)
    except socket.error as e:
        print('Cannot open socket file %s: Error "%s" (%s).' \
                % (opts.sockpath, os.strerror(e.errno), errno.errorcode.get(e.errno, 'E???')), file=sys.stderr)
        sys.exit(1)

    res = ctl.send_cmd(compose_command(opts, sys.argv))

    m = re.match('^(?P<output>.*\n)?return code (?P<code>[0-9]+)\n$', res, re.MULTILINE)
    if m:
        gd = m.groupdict()
        print(gd['output'] or '', end='')
        return_code = int(gd['code'])
        if return_code < 0 or return_code > 255:
            return_code = 1;
        sys.exit(return_code)
    else:
        print(res, end='')
        sys.exit(1)
