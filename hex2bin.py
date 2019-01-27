# -*- coding: utf-8 -*-

def ihex2b(data, buf):
    bufsize = len(buf)
    baseaddr = 0
    maxaddr = 0
    offsetaddr = 0
    nextaddr = 0

    for lineno, line in enumerate(data.splitlines()):
        if not line.startswith(":"):
            continue
        rec = ihex_readrec(line)
        if not rec:
            print("Error reading hex file")
            return False
        if rec["rectype"] == 0:
            # data record
            nextaddr = rec["loadofs"] + baseaddr
            if (nextaddr + rec["reclen"]) > (bufsize + offsetaddr):
                print("ERROR: address 0x{:04x} out of range at line {}".format(
                    nextaddr + rec["reclen"], lineno + 1
                ))
                return -1
            for i in range(rec["reclen"]):
                buf[nextaddr + i - offsetaddr] = rec["data"][i]
            if nextaddr + rec["reclen"] > maxaddr:
                maxaddr = nextaddr + rec["reclen"]

        elif rec["rectype"] == 1:
            # end of file record
            return maxaddr - offsetaddr

        elif rec["rectype"] == 2:
            # extended sgment address record
            baseaddr = rec["data"][0] << 8 | rec["data"][1] << 4

        elif rec["rectype"] == 3:
            # start segment record
            pass

        elif rec["rectype"] == 4:
            # extended linear address record
            baseaddr = rec["data"][0] << 8 | rec["data"][1] << 16
            if nextaddr == 0:
                offsetaddr = baseaddr
        elif rec["rectype"] == 5:
            # start linear address record
            pass

        else:
            raise Exception("Unknown rectype {}".format(ihex["rectype"]))

def ihex_readrec(rec):
    ihex = {
        "reclen": None,
        "loadofs": None,
        "rectype": None,
        "data": bytearray(16), # should be 256 as avrdude define
        "cksum": None
    }
    buf = bytearray(8)
    rlen = len(rec)
    offset = 1
    cksum = 0

    # reclen
    if offset + 2 > len:
        return
    ihex["reclen"] = int(rec[offset:offset + 2], 16)
    offset += 2

    # load offset
    if offset + 4 > len:
        return
    ihex["loadofs"] = int(rec[offset:offset + 4], 16)
    offset += 4

    # record type
    if offset + 2 > len:
        return
    ihex["rectype"] = int(rec[offset:offset + 2], 16)
    offset += 2

    # checksum
    cksum = (
        ihex["reclen"] +
        ((ihex["loadofs"] >> 8) & 0x0ff) +
        (ihex["loadofs"] & 0x0ff) +
        ihex["rectype"])

    # data
    for j in range(ihex["reclen"]):
        if offset + 2 > len:
            return
        ihex["data"][j] = c = int(rec[offset:offset + 2], 16)
        cksum += c
        offset += 2

    # validate checksum
    if offset + 2 > len:
        return
    ihex["cksum"] = int(rec[offset:offset + 2], 16)
    rc = -cksum & 0x000000ff
    if rc < 0:
        print("checksum issue")
        return
    if rc != ihex["cksum"]:
        print("checksum mismatch")
        return
    return ihex


def hex2bin(filename, output_filename):
    with open(filename, "rb") as fd:
        data = fd.read()
    buf = bytearray(len(data))
    size = ihex2b(data, buf)
    with open(output_filename, "wb") as fd:
        fd.write(buf[:size])
    print("Wrote {} bytes to {}".format(size, output_filename))


if __name__ == "__main__":
    import sys
    hex2bin(sys.argv[1], sys.argv[2])
