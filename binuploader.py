#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pure python implementation of STK500v1, made to work with Optiboot only.

.. author:: Mathieu Virbel <mat@meltingrocks.com>

Optiboot: https://github.com/Optiboot/optiboot/wiki/HowOptibootWorks

command ascii range: 0x00-0X7F
data ascii range: 0x00-0xFF

Commands implemented in optiboot:
STK_LOAD_ADDRESS	0x55,'U'	Note: 16bit word address, 128kb flash max.
STK_PROG_PAGE	0x64,'d'	Flash only
STK_READ_PAGE	0x74,'t'	Flash only
STK_READ_SIGN	0x75,'u'	Reads compiled-in signature.
STK_LEAVE_PROGMODE	0x51,'Q'	Starts application code via WDT reset.
STK_GET_PARAMETER	0x41,'A'	Supports "minor SW version" and "major SW version" Returns 3 for all other parameters.

baudrate for atmega328: 57600
"""

import os
import sys
import serial
import struct
import progressbar
from time import sleep

STK_LOAD_ADDRESS = 0x55
STK_PROG_PAGE = 0x64
STK_READ_PAGE = 0x74
STK_READ_SIGN = 0x75
STK_LEAVE_PROGMODE = 0x51
STK_GET_PARAMETER = 0x41

# get parameter
STK_SW_MAJOR = 0x81
STK_SW_MINOR = 0x82

STK_GET_SYNC = 0x30

Sync_CRC_EOP = 0x20
Resp_STK_INSYNC = 0x14
Resp_STK_OK = 0x10

MEM_PARTS_328P = {
    "flash": {
        "size": 32768,
        "pagesize": 128,
        "pagecount": 256,
    }
}

DEBUG = "DEBUG" in os.environ

if DEBUG:
    def debug_print(x, *largs):
        print(x.format(*largs))
else:
    def debug_print(*largs):
        pass


def autoconnect(f):
    def _autoconnect(self, *largs, **kwargs):
        try:
            self.try_connect()
            return f(self, *largs, **kwargs)
        finally:
            self.try_close()
    return _autoconnect


class ProtocolException(Exception):
    pass


class Uploader(object):
    def __init__(self, device):
        self.device = device
        self._seq = -1
        super(Uploader, self).__init__()

    def try_connect(self):
        self.con = None
        print("Connecting to bootloader...")
        self.con = serial.Serial(
            self.device,
            baudrate=57600,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=2,
            xonxoff=0,
            dsrdtr=0,
            rtscts=0)

        for x in range(3):
            try:
                self.get_sync()
                break
            except:
                pass
        print("Major: {}".format(self.get_parameter(STK_SW_MAJOR)))
        print("Minor: {}".format(self.get_parameter(STK_SW_MINOR)))
        print("Signature: 0x{:02x}{:02x}{:02x}".format(*self.read_sign()))

    def try_close(self):
        if self.con:
            self.con.close()
            self.con = None

    @autoconnect
    def upload(self, filename):
        self.filename = filename
        with open(self.filename, "rb") as fd:
            data = fd.read()

        memtype = "flash"
        mem = MEM_PARTS_328P[memtype]
        assert(mem["pagesize"] != 0)

        # convert hex to binary stored in memory
        buf = bytearray(data)
        prog_size = len(buf)

        # flash the device
        assert(mem["pagesize"] * mem["pagecount"] == mem["size"])
        progress = 0
        bar = progressbar.ProgressBar(
            widgets=[
                'Upload: ',
                progressbar.Bar(),
                ' ',
                progressbar.Counter(format='%(value)02d/%(max_value)d'),
                ' ',
                progressbar.FileTransferSpeed(),
                ' ',
                progressbar.ETA()
            ]
        )
        r = range(0, prog_size + mem["pagesize"], mem["pagesize"]) #mem["size"]
        for addr in bar(r, ):
            if addr > prog_size:
                break
            page = buf[addr:addr + mem["pagesize"]]
            self.load_addr(addr)
            self.prog_page(memtype, page)

        print("Leaving programming mode")
        self.leave_progmode()

        print("All done!")

    @autoconnect
    def dump(self):
        memtype = "flash"
        mem = MEM_PARTS_328P[memtype]
        assert(mem["pagesize"] != 0)

        # flash the device
        assert(mem["pagesize"] * mem["pagecount"] == mem["size"])
        progress = 0
        bar = progressbar.ProgressBar(
            widgets=[
                'Dump: ',
                progressbar.Bar(),
                ' ',
                progressbar.Counter(format='%(value)02d/%(max_value)d'),
                ' ',
                progressbar.FileTransferSpeed()
            ]
        )
        r = range(0, mem["size"], mem["pagesize"])
        with open("dump.hex", "wb") as fd:
            for addr in bar(r, ):
                data = bytearray(b"0" * 128)
                self.load_addr(addr)
                self.read_page(memtype, data)
                fddata = "".join(["{:02x}".format(x) for x in data])
                fd.write(fddata)
                fd.write("\n")
                debug_print("[STK500] DATA {}".format(fddata))

        print("Leaving programming mode")
        self.leave_progmode()

        print("All done, go into dump.hex")

    def load_addr(self, addr):
        debug_print("[STK500] Load address {:06x}".format(addr))
        addr = addr / 2
        pkt = struct.pack(
            "BBBB",
            STK_LOAD_ADDRESS,
            addr & 0xff,
            (addr >> 8) & 0xff,
            Sync_CRC_EOP)
        self.write(pkt)
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("load_addr() can't get into sync")
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("load_addr() protocol error")

    def prog_page(self, memtype, data):
        debug_print("[STK500] Prog page")
        assert(memtype == "flash")
        block_size = len(data)
        pkt = struct.pack(
            "BBBB",
            STK_PROG_PAGE,
            (block_size >> 8) & 0xff,
            block_size & 0xff,
            ord("F"),  # because flash, othersize E for eeprom
        )
        pkt += data
        pkt += struct.pack("B", Sync_CRC_EOP)
        self.write(pkt)
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("prog_page() can't get into sync")
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("prog_page() protocol error")

    def read_page(self, memtype, data):
        debug_print("[STK500] Read page")
        assert(memtype == "flash")
        block_size = len(data)
        pkt = struct.pack(
            "BBBBB",
            STK_READ_PAGE,
            (block_size >> 8) & 0xff,
            block_size & 0xff,
            ord("F"),  # because flash, othersize E for eeprom
            Sync_CRC_EOP
        )
        self.write(pkt)
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("read_page() can't get into sync")
        data[:] = self.read(block_size)
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("read_page() protocol error")

    def get_sync(self):
        debug_print("[STK500] Get sync")
        pkt = struct.pack("BB", STK_GET_SYNC, Sync_CRC_EOP)
        for i in range(5):
            sleep(.3)
            self.con.flush()
            self.write(pkt)
            try:
                if self.readbyte() != Resp_STK_INSYNC:
                    raise ProtocolException("read_page() can't get into sync")
                if self.readbyte() != Resp_STK_OK:
                    raise ProtocolException("read_page() protocol error")
                print("Connected to bootloader")
                return
            except Exception as e:
                pass
        raise ProtocolException("STK500: cannot get sync")

    def get_parameter(self, param):
        debug_print("[STK500] Get parameter {:x}".format(param))
        self.write(struct.pack("BBB", STK_GET_PARAMETER, param, Sync_CRC_EOP))
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("get_parameter() can't get into sync")
        val = self.readbyte()
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("get_parameter() protocol error")
        return val

    def read_sign(self):
        debug_print("[STK500] Read signature")
        self.write(struct.pack("BB", STK_READ_SIGN, Sync_CRC_EOP))
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("read_sign() can't get into sync")
        sign = struct.unpack("BBB", self.read(3))
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("read_sign() protocol error")
        return sign

    def leave_progmode(self):
        debug_print("[STK500] Leaving programming mode")
        pkt = struct.pack("BB",
            STK_LEAVE_PROGMODE,
            Sync_CRC_EOP)
        self.write(pkt)
        if self.readbyte() != Resp_STK_INSYNC:
            raise ProtocolException("leave_progmode() can't get into sync")
        if self.readbyte() != Resp_STK_OK:
            raise ProtocolException("leave_progmode() protocol error")

    def readbyte(self):
        while True:
            ret = self.read(1)
            if ret != b'!':
                b = struct.unpack("B", ret)[0]
                return b

            buf = b''
            index = 0
            while True:
                # print("readbyte line")
                ret = self.read(1)
                # print("ret=", ret)
                if ret == b'\n':
                    if buf:
                        buf = buf.replace(b'\r', '')
                        print("[......] {!r}".format(buf))
                    break
                buf += ret

    def read(self, size):
        read = 0
        buf = bytearray(b"\x00" * size)
        while read < size:
            ret = self.con.read(size - read)
            if ret == "":
                raise Exception("no data read, timeout? (read={} wanted={})".format(
                    read, size))
            buf[read:read + len(ret)] = ret
            read += len(ret)
        return bytes(buf[:read])

    def write(self, pkt):
        pkt = bytearray(pkt)
        debug_print("[STK500] Packet[{}] {}".format(len(pkt), " ".join(
            ["{:02x}".format(x) for x in pkt])))

        # don't write too fast or we loose data
        for i in range(0, len(pkt), 32):
            self.con.write(pkt[i:i + 32])
            sleep(0.05)


def upload(device, filename):
    while True:
        try:
            Uploader(device).upload(filename)
            break
        except ProtocolException as e:
            print(e)
        except Exception as e:
            print(e)
            sleep(1)


def dump(device):
    while True:
        try:
            Uploader(device).dump()
            break
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(e)
            sleep(1)


if __name__ == "__main__":
    if sys.argv[1] == "upload":
        upload(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "dump":
        dump(sys.argv[2])