#!/usr/bin/env python

import socket
import re
import sys
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
        self.sock.send("quit")
        #self.file_obj.close()
        self.sock.close()


def setup(option, opt_str, value, parser):
    if parser.values.cmd != None:
        parser.print_help()
        sys.exit(2)

    if opt_str == "-l":
        parser.values.cmd = "list"

    elif opt_str == "-a":
        parser.values.cmd = "add " + value

    elif opt_str == "-d":
        parser.values.cmd = "del " + value


if __name__ =='__main__':

    clparser = OptionParser(usage="\n  %prog [-s SOCKPATH] -l\n"
                                   +"  %prog [-s SOCKPATH] -a FILE\n"
                                   +"  %prog [-s SOCKPATH] -d N")
    clparser.set_defaults(cmd=None)
    clparser.add_option("-l", action="callback", callback=setup, nargs=0, 
                        help="list disk images")
    clparser.add_option("-a", action="callback", callback=setup, nargs=1, 
                        help="add disk image file", 
                        type="string", metavar="FILE")
    clparser.add_option("-d", action="callback", callback=setup, nargs=1, 
                        help="delete disk image file. N is the diskimage number on the list", 
                        type="int", metavar="N")
    clparser.add_option("-s", 
                        help="specify socket file path", 
                        dest="sockpath", default="/tmp/xnbd_wrapper.ctl")
    (opts, args) = clparser.parse_args()

    if opts.cmd == None:
        clparser.print_help()
        sys.exit(2)

    ctl = XNBDWrapperCtl(opts.sockpath)
    print ctl.send_cmd(opts.cmd),

