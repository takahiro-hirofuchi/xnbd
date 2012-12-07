#!/usr/bin/env python


# xNBD - an enhanced Network Block Device program
# 
# Copyright (C) 2008-2012 National Institute of Advanced Industrial Science
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


import socket
import re
import sys
import os
import errno
import copy

try:
    import argparse
except ImportError:
    print >> sys.stderr, 'ERROR: Python >=2.7 or python-argparse needed to run'
    sys.exit(1)


def prog(argv_zero):
    return os.path.basename(argv_zero)


class XNBDWrapperCtl:

    pattern = ".*\(xnbd\) "

    def __init__(self, sockpath):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sockpath)
        self.sock.recv(54)
        self.sock.settimeout(0.2)
        #self.file_obj = self.sock.makefile()

    def _read_response(self):
        #buf = []
        buf = ""
        limit = 10
        for i in range(limit):
            #line = self.file_obj.readline()
            try:
                buf += self.sock.recv(4096)
            except:
                continue
            if re.search(self.pattern, buf, re.S):
                return re.sub("\(xnbd\) ", "", buf)
        sys.stderr.write("timeout or too many data\n")
        return buf

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
  %(prog)s [-s SOCKPATH] --add FILE
  %(prog)s [-s SOCKPATH] [--target-exportname NAME] --add-proxy TARGET_HOST TARGET_PORT CACHE_IMAGE BITMAP_IMAGE CONTROL_SOCKET_PATH
  %(prog)s [-s SOCKPATH] --remove INDEX
  %(prog)s [-s SOCKPATH] --shutdown
""")

    operations = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument("-s", "--socket",
                        dest="sockpath", default="/tmp/xnbd_wrapper.ctl",
                        help="specify the socket file path of xnbd-wrapper.")

    operations.add_argument("--list", "-l", action='store_true',
                        help="list registered disk images.")
    operations.add_argument("--add", "-a", metavar='FILE',
                        help="add a disk image file to the export list.")
    operations.add_argument("--add-proxy", metavar=['TARGET_HOST', 'TARGET_PORT', 'CACHE_IMAGE', 'BITMAP_IMAGE', 'CONTROL_SOCKET_PATH'], nargs=5,
                        help="add a disk image file to the export list.")
    operations.add_argument("--remove", "-r", metavar='INDEX', type=int,
                        help="remove a disk image file from the list.")
    operations.add_argument("--shutdown", "-d", action='store_true',
                        help="remove all disk images from the xnbd-wrapper instance and stop it afterwards.")

    parser.add_argument("--target-exportname", metavar='NAME',
                        help="set the export name to request from a xnbd-wrapper target (used with --add-proxy).")

    options = parser.parse_args(argv[1:])

    if options.target_exportname and not options.add_proxy:
        print >>sys.stderr, '%s: error: Argument --target-exportname is only supported in combination with --add-proxy.' % prog(argv[0])
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

    # Single argument commands
    single_arg_commands = (
        (options.add, 'add'),
        (options.remove, 'del'),
    )
    for dest, command_name, in single_arg_commands:
        if dest:
            return '%s %s' % (command_name, dest)

    # More complex commands
    if options.add_proxy:
        args = copy.copy(options.add_proxy)
        if options.target_exportname:
            args.append(options.target_exportname)

        # Make sure that spaces do not cause trouble without notice
        args_with_spaces = [v for v in args if ' ' in v]
        if args_with_spaces:
            if len(args_with_spaces) == 1:
                details = '"%s"' % args_with_spaces[0]
            else:
                details = ', '.join([('"%s"' % v) for v in args_with_spaces])
            print >>sys.stderr, '%s: error: Arguments containing spaces (%s) are not supported, sorry.' % (prog(argv[0]), details)
            sys.exit(1)

        return 'add-proxy %s' % ' '.join(args)

    assert False, 'Internal error, no command used'


if __name__ =='__main__':
    opts = parse_command_line(sys.argv)

    try:
        ctl = XNBDWrapperCtl(opts.sockpath)
    except socket.error as e:
        print 'Cannot open socket file %s: Error "%s" (%s).' \
                % (opts.sockpath, os.strerror(e.errno), errno.errorcode.get(e.errno, 'E???'))
        sys.exit(1)

    res = ctl.send_cmd(compose_command(opts, sys.argv))
    if not re.match("^ *(|\n)$", res):
        print res,

