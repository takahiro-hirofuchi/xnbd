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

from __future__ import print_function

import socket
import re
import sys
import os
import errno
import urllib

try:
    import argparse
except ImportError:
    print('ERROR: Python >=2.7 or python-argparse needed to run', file=sys.stderr)
    sys.exit(1)


def prog(argv_zero):
    return os.path.basename(argv_zero)


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
  %(prog)s [-s SOCKPATH] [--local-exportname NAME] --add FILE
  %(prog)s [-s SOCKPATH] [--local-exportname NAME] [--target-exportname NAME] --add-proxy TARGET_HOST TARGET_PORT CACHE_IMAGE BITMAP_IMAGE CONTROL_SOCKET_PATH
  %(prog)s [-s SOCKPATH] --remove INDEX
  %(prog)s [-s SOCKPATH] --remove-by-file FILE
  %(prog)s [-s SOCKPATH] --remove-by-exportname NAME
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
    operations.add_argument("--remove-by-file", metavar='FILE',
                        help="remove a disk image file from the list.")
    operations.add_argument("--remove-by-exportname", metavar='NAME',
                        help="remove a disk image file from the list.")
    operations.add_argument("--shutdown", "-d", action='store_true',
                        help="remove all disk images from the xnbd-wrapper instance and stop it afterwards.")

    parser.add_argument("--local-exportname", metavar='NAME',
                        help="set the export name to export the image as.")
    parser.add_argument("--target-exportname", metavar='NAME',
                        help="set the export name to request from a xnbd-wrapper target (used with --add-proxy).")

    options = parser.parse_args(argv[1:])

    if options.target_exportname and not options.add_proxy:
        print('%s: error: Argument --target-exportname is only supported in combination with --add-proxy.' % prog(argv[0]), file=sys.stderr)
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
        (options.remove, 'del'),
        (options.remove_by_file, 'del-file'),
        (options.remove_by_exportname, 'del-exportname'),
    )
    for dest, command_name, in single_arg_commands:
        if dest:
            encoded_arg = urllib.quote(str(dest))
            return '%s %s' % (command_name, encoded_arg)

    # More complex commands
    if options.add_proxy:
        args = []
        if options.local_exportname:
            # export name != file name  (possibly)
            args.append(options.local_exportname)
        else:
            # export name == file name
            target_host, target_port, cache_image, bitmap_image, control_socket_path = options.add_proxy
            args.append(cache_image)
        args.extend(options.add_proxy)
        if options.target_exportname:
            args.append(options.target_exportname)

        encoded_args = [urllib.quote(e) for e in args]
        return 'add-proxy %s' % ' '.join(encoded_args)
    elif options.add:
        args = []
        if options.local_exportname:
            # export name != file name  (possibly)
            args.append(options.local_exportname)
        args.append(options.add)

        encoded_args = [urllib.quote(e) for e in args]
        return 'add %s' % ' '.join(encoded_args)

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
    if not re.match("^ *(|\n)$", res):
        print(res, end='')
