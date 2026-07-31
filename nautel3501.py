#!/usr/bin/env python3
"""Decoder for the Nautel AUI binary protocol on TCP/3501.

Usage:
    tshark -r cap.pcapng -q -z follow,tcp,raw,<stream> > raw.txt
    python3 nautel3501.py raw.txt tx_spec.xml

tx_spec.xml comes from http://<tx>/bin/com/nautel/aui/assets/configs/vs/tx_spec.xml
and supplies the chanID -> name mapping.
"""
import re
import struct
import sys

FLAG_START, FLAG_END, FLAG_ESC = 0xFF, 0xFE, 0xFD

# Device bases: base = parent_base + offsetFromParent, siblings step by
# offsetFromSibling. Derived from tx_spec.xml <device> attributes.
DEVICE_BASE = {
    0x01000000: "CONTROLLER",
    0x02010000: "EXCITER",
    0x03010000: "EXCITER",
    0x04010000: "EXCITER",
    0x01010000: "HD_EXCITER",
    0x040B0000: "ORBAN_AUDIO_PROCESSOR",
    0x040E0000: "EXGINE",
}

CLIENT_MSG = {
    0x00: "READ",           # one-shot read: u16 count + N channel IDs
    0x03: "SUBSCRIBE",      # add IDs to the pushed set
    0x05: "SUBSCRIBE_ARRAY",
    0x09: "HELLO",
    0x13: "LOGIN",
}
SERVER_MSG = {
    0x0B: "DATA",           # u16 count + N (ID, value) pairs
    0x0D: "SUBSCRIPTION",   # current subscription set, u16 count + N IDs
    0x0F: "HELLO_ACK",
    0x14: "USER",
}


def load_channels(spec_path):
    """chanID -> name, per device fID."""
    xml = open(spec_path).read()
    chans, cur = {}, None
    pat = r'<device\s+[^>]*fID="([A-Z_]+)"[^>]*>|<channel\s+fID="([^"]+)"\s+chanID="([^"]+)"'
    for m in re.finditer(pat, xml, re.S):
        if m.group(1):
            cur = m.group(1)
            chans[cur] = {}
        else:
            chans[cur][int(m.group(3), 16)] = m.group(2)
    return chans


def channel_name(chans, cid):
    base, chan = cid & 0xFFFF0000, cid & 0xFFFF
    dev = DEVICE_BASE.get(base)
    if dev and chan in chans.get(dev, {}):
        return f"{dev}[{base >> 16:04x}].{chans[dev][chan]}"
    for dev, table in chans.items():
        if chan in table:
            return f"?{base:08x}?.{table[chan]}"
    return f"UNKNOWN:{cid:08x}"


def load_follow(path):
    """Split a `tshark -z follow,tcp,raw` dump into (client, server) byte streams."""
    client = bytearray()
    server = bytearray()
    for line in open(path):
        line = line.rstrip("\n")
        if not line or line[0] == "=" or line.startswith(("Follow", "Filter", "Node")):
            continue
        is_server = line.startswith("\t")
        hexstr = line.strip()
        if not re.fullmatch(r"[0-9a-f]*", hexstr):
            continue
        (server if is_server else client).extend(bytes.fromhex(hexstr))
    return bytes(client), bytes(server)


def frames(buf):
    """Yield (msg_type, payload) per FF ... FE frame, undoing FD escaping.

    Escaped bytes are encoded FD 00/01/02 for FD/FE/FF; the escape byte
    carries the original minus 0xFD. Framing alone cannot distinguish this
    from other offsets, so it was pinned down against EX_SPECTRUM_FREQUENCY,
    whose contents are a known linear ramp (-500000 Hz, 1000 Hz steps).
    Decoded frame is: u16le length | u16 reserved (0) | u8 type | payload,
    where length == len(payload) + 1 (it counts the trailing FE).
    """
    i = 0
    while i < len(buf):
        if buf[i] != FLAG_START:
            raise ValueError(f"desync at {i}: {buf[i]:#04x}")
        j = i + 1
        dec = bytearray()
        while j < len(buf) and buf[j] != FLAG_END:
            if buf[j] == FLAG_ESC:
                dec.append((buf[j + 1] + 0xFD) & 0xFF)
                j += 2
            else:
                dec.append(buf[j])
                j += 1
        if j >= len(buf):
            return  # truncated tail
        yield dec[4], bytes(dec[5:])
        i = j + 1


def parse_ids(payload):
    n = struct.unpack_from("<H", payload, 0)[0]
    return [struct.unpack_from("<I", payload, 2 + 4 * k)[0] for k in range(n)]


def parse_values(payload):
    """Yield (channel_id, header, data) for a DATA message.

    Each value is u16le total_len | u16le header_len | header | data.
    Scalar channels use header_len 5: u32le unix seconds + u8 hundredths.
    Array channels (spectrum, mod vector, LMS filter) use 14/16/32-byte headers.
    """
    n = struct.unpack_from("<H", payload, 0)[0]
    off = 2
    for _ in range(n):
        cid = struct.unpack_from("<I", payload, off)[0]
        off += 4
        total, hlen = struct.unpack_from("<HH", payload, off)
        off += 4
        yield cid, payload[off:off + hlen], payload[off + hlen:off + total]
        off += total


def decode_timestamp(header):
    if len(header) != 5:
        return None
    return struct.unpack("<I", header[:4])[0] + header[4] / 100.0


def main():
    chans = load_channels(sys.argv[2])
    client, server = load_follow(sys.argv[1])
    for label, buf, names in (("C->S", client, CLIENT_MSG), ("S->C", server, SERVER_MSG)):
        for mtype, payload in frames(buf):
            kind = names.get(mtype, f"type{mtype:#04x}")
            if kind == "DATA":
                for cid, hdr, data in parse_values(payload):
                    ts = decode_timestamp(hdr)
                    stamp = f"{ts:.2f}" if ts else "-"
                    print(f"{label} {kind:14} {stamp:>14} "
                          f"{channel_name(chans, cid):55} {data[:16].hex(' ')}"
                          f"{' ...' if len(data) > 16 else ''}")
            elif kind in ("READ", "SUBSCRIBE", "SUBSCRIBE_ARRAY", "SUBSCRIPTION"):
                ids = ", ".join(channel_name(chans, i) for i in parse_ids(payload))
                print(f"{label} {kind:14} {'':>14} [{ids}]")
            else:
                print(f"{label} {kind:14} {'':>14} {payload[:48].hex(' ')}")


if __name__ == "__main__":
    main()
