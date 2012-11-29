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
from optparse import OptionParser


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


def setup(option, opt_str, value, parser):
    if parser.values.cmd != None:
        parser.print_help()
        sys.exit(2)

    if opt_str == "-l" or opt_str == "--list":
        parser.values.cmd = "list"

    elif opt_str == "-d" or opt_str == "--shutdown":
        parser.values.cmd = "shutdown"

    elif opt_str == "-a" or opt_str == "--add":
        parser.values.cmd = "add " + value

    elif opt_str == "-r" or opt_str == "--remove":
        if re.match("^[1-9][0-9]+$|^[0-9]$", value) == None:
            parser.print_help()
            sys.exit(2)
        parser.values.cmd = "del " + value


if __name__ =='__main__':

    clparser = OptionParser(usage="\n  %prog [-s SOCKPATH] --list\n"
                                   +"  %prog [-s SOCKPATH] --add FILE\n"
                                   +"  %prog [-s SOCKPATH] --remove N\n"
                                   +"  %prog [-s SOCKPATH] --shutdown")
    clparser.set_defaults(cmd=None)
    clparser.add_option("-l", "--list", action="callback", callback=setup, nargs=0, 
                        help="list registered disk images.")
    clparser.add_option("-a", "--add", action="callback", callback=setup, nargs=1, 
                        help="add a disk image file to the export list.", 
                        type="string", metavar="FILE")
    clparser.add_option("-r", "--remove", action="callback", callback=setup, nargs=1, 
                        help="remove a disk image file from the list. N is the index number on the list.", 
                        type="string", metavar="N")
    clparser.add_option("-s", "--socket",
                        help="specify the socket file path of xnbd-wrapper.", 
                        dest="sockpath", default="/tmp/xnbd_wrapper.ctl")
    clparser.add_option("-d", "--shutdown", action="callback", callback=setup, nargs=0, 
                        help="remove all disk images from the xnbd-wrapper instance and stop it afterwards.")
    (opts, args) = clparser.parse_args()

    if opts.cmd == None:
        clparser.print_help()
        sys.exit(2)

    try:
        ctl = XNBDWrapperCtl(opts.sockpath)
    except socket.error as e:
        print 'Cannot open socket file %s: Error "%s" (%s).' \
                % (opts.sockpath, os.strerror(e.errno), errno.errorcode.get(e.errno, 'E???'))
        sys.exit(1)

    res = ctl.send_cmd(opts.cmd)
    if not re.match("^ *(|\n)$", res):
        print res,

