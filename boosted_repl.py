#!/usr/bin/env python
from __future__ import print_function
import readline
import os
import re
import functools
import sys
import code
import random
import math
import time
import signal
import argparse
from threading import Thread
import gevent
# from gevent.fileobject import FileObject
# from gevent.greenlet import Greenlet
from gevent.queue import Queue
from binascii import unhexlify
from PyBT.roles import LE_Central
from PyBT.stack import BTEvent
from PyBT.gap import GAP

import subprocess
from jammer import Jammer
from scapy.layers.bluetooth import HCI_Cmd_Reset

from gevent.select import select
# this is hack because the above does not work
from gevent import monkey
monkey.patch_select()
monkey.patch_sys()

signal.signal(signal.SIGINT, lambda *x: os._exit(1))

SEEN = {}
DISCONNECTED = 0
CONNECTED = 1
PROMPT = "> "
LIMIT = None

BANNER = """\

     ***** ***                             **
  ******  * **                              **
 **   *  *  **                              **
*    *  *   **                              **
    *  *    *      ****                     **
   ** **   *      * ***  *    ****      *** **
   ** **  *      *   ****    * ***  *  *********
   ** ****      **    **    *   ****  **   ****
   ** **  ***   **    **   **    **   **    **
   ** **    **  **    **   **    **   **    **
   *  **    **  **    **   **    **   **    **
      *     **  **    **   **    **   **    **
  ****      ***  ******    **    **   **    **
 *  ****    **    ****      ***** **   *****
*    **     *                ***   **   ***
*
 **

       ***** ***                          *
    ******  * **                        **
   **   *  *  **                        **
  *    *  *   **                        **
      *  *    *                 ****    **
     ** **   *       ****      * **** * **  ***
     ** **  *       * ***  *  **  ****  ** * ***
     ** ****       *   ****  ****       ***   ***
     ** **  ***   **    **     ***      **     **
     ** **    **  **    **       ***    **     **
     *  **    **  **    **         ***  **     **
        *     **  **    **    ****  **  **     **
    ****      *** **    **   * **** *   **     **
   *  ****    **   ***** **     ****    **     **
  *    **     *     ***   **             **    **
  *                                            *
   **                                         *
                                             *
                                            *
"""

class FakeQueue(object):
    def get(self):
        pass
    def put(self, _):
        pass

QUEUE = Queue()

def dump_gap(data):
    if len(data) > 0:
        try:
            gap = GAP()
            gap.decode(data)
            info("GAP: %s" % gap)
        except Exception as e:
            err(repr(e))
            pass

def trap_exception(func):
    @functools.wraps(func)
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt as e:
            os._exit(1)
        except Exception as e:
            err(repr(e))
            os._exit(1)
    return inner


def mklog(c):
    def inner(m):
        cur = readline.get_line_buffer()
        sys.stdout.write(chr(0x8) * 120)
        sys.stdout.flush()
        print('[' + c + '] ' + m)
        sys.stdout.write(PROMPT)
        sys.stdout.write(cur)
        sys.stdout.flush()
    return inner

log = mklog('+')
info = mklog(' ')
err = mklog('!')
log_out = mklog('<')
log_in = mklog('>')
msg = mklog('%')
unknown = mklog('?')

DIFFICULTY = {
        'A': "Beginner",
        'B': "Eco",
        'C': "Expert",
        'D': "Pro",
        }


def _argparser():
    parser = argparse.ArgumentParser(description='Boosted Repl')
    parser.add_argument('-i', '--interface', dest='interface', action='store',
                        type=int, help='Interface to use', default=0)

    parser.add_argument('addr', action='store', help='Bluetooth address')
    return parser

class BoostedInteractor(object):
    def __init__(self, central):
        log("initializing a %s" % self.__class__.__name__)
        self.central = central
        self.cb = None

    def handshake(self):
        log("Configuring Client Characteristics")
        self.central.att.write_cmd(handle=0x0f, value="\x02\x00")
        self.central.att.write_cmd(handle=0x1d, value="\x02\x00")
        self.central.att.write_req(handle=0x22, value="\x10\x10")
        self.central.att.write_req(handle=0x18, value="\x01")

        if self.cb:
            self.cb()
        log("Handshake complete")

    @trap_exception
    def start(self):
        log("Starting repl")
        self.handshake()
        self.main()

class Repl(BoostedInteractor):
    def __init__(self, central, parser):
        self.parser = parser
        super(Repl, self).__init__(central)

        self.CMDS = {
                "die": self.die,
                "o1": self.oh_one,
                "o2": self.oh_two,
                "help": self.help,
                "fuel": self.fuel,
                "ping": self.ping,
                "atv": self.atv,
                "atsc": self.atsc,
                "git": self.git,
                "stat": self.stat,
                "raw": self.raw,
                "raws": self.raws,
                "numskl": self.numskl,
                "soc": self.soc,
                "socping": self.socping,
                "odo": self.odo,
                "rc0": self.rc0,
                "rexp": self.rexp,
                "rbgn": self.rbgn,
                "readfile": self.readfile,
                "spin": self.spin,
                }

        # self.cb = self.atsc

    def send(self, payload, handle=0x1a):
        mklog("< %x" % handle)(repr(payload))
        self.central.att.write_req(handle=handle, value=payload)
        # This queue is dumb because other shit gets written into it
        QUEUE.get()

    def die(self):
        """die: Kill the repl process"""
        log("Taking out session")
        os._exit(1)

    def help(self):
        """help: Print this help"""
        for cmd in self.CMDS.values():
            info(cmd.__doc__)

    def fuel(self):
        """fuel: Ask the board how much fuel it has left"""
        self.parser.show_battery = True
        self.send("FUEL\x0d")

    def ping(self):
        """ping: Ping the board"""
        self.send("PING\x0d")

    def atv(self):
        """atv: ATV? Literally no idea"""
        self.send("ATV?\x0d")

    def oh_one(self):
        """01: Write 0x01 to handle 0x18"""
        self.send("\x01", handle=0x18)

    def oh_two(self):
        """02: Write 0x02 to handle 0x18"""
        self.send("\x01", handle=0x18)
        self.send("\x02", handle=0x18)

    def atsc(self):
        """atsc: Send some rando ATSC thing I foundi n wireshark"""
        raw = "41:54:53:43:43:50:2c:30:2c:38:2c:31:36:2c:30:2c:37:35:0d"
        payload = ''.join(map(chr, map(lambda x: int(x, 16), raw.split(":"))))
        self.send(payload)

    def git(self):
        """git: Get the git revision of the loaded firmware"""
        self.send("GIT\x0d")

    def stat(self):
        """stat: Retrieve stats about the board"""
        self.send("STAT\x0d")

    def raw(self, byts):
        """raw string: send `string` as bytes, adding a \r"""
        self.send(byts + "\x0d")

    def raws(self, byts):
        """raw string: send `string` as bytes, removing all spaces, adding a \r"""
        self.send(byts.replace(" ", "") + "\x0d")

    def numskl(self):
        """numskl: Number of skill settings"""
        self.send("NUMSKL\x0d")

    def soc(self):
        """soc: Read battery percent"""
        self.parser.read_battery = True
        self.send("SOC\x0d")

    def socping(self):
        """socping: Send a soc and a ping at once in case something good happens"""
        self.send("SOC\x0dPING\x0d")

    def odo(self):
        """odo: get odo reading"""
        self.send("ODO\x0d")

    def rc0(self):
        """rc0: fetch board state"""
        self.send("RC00000\x0d")

    def rexp(self):
        """rexp: Poke the board into expert mode"""
        self.send("REXP\x0d")

    def rbgn(self):
        """rbgn: Poke the board into beginner mode"""
        self.send("rbgn\x0d")

    def spin(self):
        """spin: Spin the wheels a little"""
        def spam():
                                                          # rc0 + speed + crc
            self.central.att.write_req(handle=0x1a, value="\x52\x43\x301405" + "\x0d")
            QUEUE.get()
        for _ in range(30):
                spam()

    def readfile(self, filename, sleeptime=0):
        """readfile filename: Read the contents of filename and send as raw bytes on the connection"""
        try:
            # Arguments all come in as strings, although helpfully the existing
            # try catch machinery will do something reasonable looking if this
            # gets an invalid error
            sleeptime = float(sleeptime)
            with open(filename) as fh:
                while True:
                    line = fh.readline().strip()
                    if not line: return
                    self.send(unhexlify(line))

                    if sleeptime > 0:
                        gevent.sleep(sleeptime)
        except Exception as e:
            err(repr(e))

    def unknown(self, cmd):
        err("Unknown command: %s" % cmd)

    def argerror(self, cmd):
        err("Wrong number of arguments:")
        err(cmd.__doc__)

    def main(self):
        while True:
            cmd = raw_input(PROMPT)
            try:
                cmd, args = cmd.split(" ", 1)
                args = args.split(" ")
            except ValueError:
                args = []

            try:
                self.CMDS[cmd](*args)
            except KeyError:
                self.unknown(cmd)
            except TypeError:
                self.argerror(self.CMDS[cmd])


class MessageBuffer(object):
    """A message buffer has a simple `push` interface, and accepts a callback
    for what to do with completed messages"""

    SEP = "\r\n"

    def __init__(self, cb):
        self.cb = cb
        self.buffer = ""

    def push(self, payload):
        self.buffer += payload
        self.flush()

    def flush(self):
        # This is kinda a hack, lots of messages are actually \r\n delimited
        # if self.SEP in self.buffer:
        if "\n" in self.buffer or "\r" in self.buffer:
            # omfg, why
            push = False
            parts = re.split('[\r\n]', self.buffer)
            if parts[-1] == '': # Last element was a delimeter
                push = True
            parts = filter(lambda x: x, parts)

            if push:
                self.buffer = ""
            else:
                self.buffer = parts.pop()

            map(lambda x: self.cb(x), parts)

class MessageParser(object):
    def __init__(self, log, unknown):
        self.log = log
        self.unknown = unknown
        #
        self.show_battery = False
        self.read_battery = False

    def parse(self, msg):
        # Try parsing against obvious things that we know about, if all else
        # fails just log the raw message
        if msg.startswith("GAUGE"):
            if self.show_battery:
                self.show_battery = False
                amount = int(msg[5])
                self.log("Charged at least %%%d (%s)" % (20 * amount, repr(msg)))
        # The way this state machine works is kinda handwavy, in the above
        # case, the parse is unambiguous but we might want to ignore it. Here
        # this could be anything so we try to be careful
        elif self.read_battery and len(msg) == 2:
            self.read_battery = False
            batt = int(msg, 16)
            self.log("Charged exactly %%%d (%s)" % (batt, repr(msg)))
        elif msg.startswith("RCO"):
            self.log("RCO: preamble(?)")
            self.log("K: ?")
            if msg[-2] == "O":
                self.log("O: Board is on the charger")
            else:
                self.log("K: Board is not on the charger")
            self.log("%s: Board is in %s mode" % (msg[-1], DIFFICULTY[msg[-1]]))
            self.log(repr(msg))

        else:
            self.unknown(msg)


class Handler(object):
    def __init__(self, central, target):
        self.central = central
        self.connected = False
        self.target = target
        self.parser = MessageParser(msg, unknown)
        self.buffer = MessageBuffer(self.parser.parse)
        # If True, then instead of launching a repl just go and do some haxxing

    def connect(self):
        log("Connecting to %s:public" % self.target)
        # type = SEEN[self.target][0] # maybe we saw it when advertising
        info(repr((self.target, type)))
        self.central.stack.connect(self.target, 'public')

    def reset(self):
        self.central.stack.command(HCI_Cmd_Reset())
        log("Sent reset")

    def onconnect(self):
        log("Standing up repl")
        repl = Repl(self.central, self.parser)
        gevent.spawn(repl.start)

    @trap_exception
    def socket_handler(self):
        log("Reactor thread started")
        self.connect()
        while True:
            select([self.central.stack], [], [])
            event = self.central.stack.handle_data()
            if event.type == BTEvent.SCAN_DATA:
                addr, type, data = event.data
                log("Saw %s (%s)" % (addr, "public" if type == 0 else "random"))
                try:
                    if len(data) > len(SEEN[addr][1]):
                        SEEN[addr] = (type, data)
                        dump_gap(data)
                except KeyError:
                    SEEN[addr] = (type, data)
                    dump_gap(data)
                if addr.lower() == self.target.lower() and self.connected == False:
                    pass

            elif event.type == BTEvent.CONNECTED:
                self.connected = True
                log("Connected!")
                self.onconnect()
            elif event.type == BTEvent.DISCONNECTED:
                self.connected = False
                log("Disconnected")
                log("Attempting reconnection")
                self.connect()
                #self.reset()
                # log("Reset")

            elif event.type == BTEvent.ATT_DATA:
                pkt = event.data
                # ack handle value notification
                if pkt.opcode == 0x1d:
                    self.central.stack.raw_att("\x1e")
                    handle = pkt.payload.load[0]
                    null = pkt.payload.load[1]
                    body = pkt.payload.load[2:]
                    # log_in("%x : %s" % (ord(handle), repr(body)))
                    mklog("< %x" % ord(handle))(repr(body))
                    self.buffer.push(body)
                elif pkt.opcode == 0x13:
                    QUEUE.put(1)
            elif event.type != BTEvent.NONE:
                log(repr(event))


def main():
    global LIMIT
    if not os.getenv("NOBANNER"):
        log(BANNER)
    parser = _argparser()
    args = parser.parse_args()
    addr = args.addr
    log("Will connect to %s when seen" % addr)
    central = LE_Central(adapter=args.interface)
    handler = Handler(central, addr)
    log("Starting reactor thread")
    gevent.spawn(handler.socket_handler)
    # log("Enabling scan")
    # central.stack.scan()

    ret = gevent.wait()
    log("Gevent exited")
    log(repr(ret))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        os._exit(1)
