#!/usr/bin/env python3
"""Bridge the Nautel AUI TCP/3501 protocol to a browser.

Live against a transmitter:
    python3 nautel_bridge.py --host 192.168.10.1 --user Nautel --password secret
    NAUTEL_PASSWORD=secret python3 nautel_bridge.py --host 192.168.10.1

Replay a capture (uses tshark; --spec-host fetches the channel spec once):
    python3 nautel_bridge.py --replay nautel.pcapng --spec-host 192.168.10.1

Synthetic data, for working on the UI with nothing attached:
    python3 nautel_bridge.py --demo --spec-host 192.168.10.1

The transmitter serves tx_spec.xml, so it never has to be distributed: live mode
fetches it, --demo/--replay take --spec-host (cached to .tx_spec.cache.xml for
offline reuse) or an explicit --spec <file>.

Then open http://localhost:8531/.

Only reads are implemented, by choice. The write encoding is known and
documented (docs/PROTOCOL.md) but no write path is wired up, so this cannot
change transmitter state.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import random
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

FLAG_START, FLAG_END, FLAG_ESC = 0xFF, 0xFE, 0xFD
ESCAPED = {FLAG_ESC: 0x00, FLAG_END: 0x01, FLAG_START: 0x02}

MSG_READ, MSG_SUBSCRIBE, MSG_HELLO, MSG_LOGIN = 0x00, 0x03, 0x09, 0x13
MSG_DATA, MSG_SUBSCRIPTION, MSG_HELLO_ACK, MSG_USER = 0x0B, 0x0D, 0x0F, 0x14

DEVICE_BASE = {
    "CONTROLLER": 0x01000000,
    "EXCITER": 0x04010000,
    "HD_EXCITER": 0x01010000,
    "ORBAN_AUDIO_PROCESSOR": 0x040B0000,
    "EXGINE": 0x040E0000,
}

# Array channels: name -> (element format, scale, kind).
# Values are little-endian; the AUI plots them at 0.01 units per count.
ARRAY_CHANNELS = {
    "EX_SPECTRUM_AMPLITUDE": ("h", 0.01, "spectrum"),
    "EX_SPECTRUM_MASK_AMPLITUDE": ("h", 0.01, "mask"),
    "EX_LMS_FILTER_FREQDOMAIN": ("h", 0.01, "eq_freq"),
    # 16 filter taps as interleaved (real, imag) int32 - the tap count and
    # interleave are confirmed by the shape (a clean impulse decaying to zero
    # at both edges) and the AUI's 0-15 tap axis. The amplitude divisor is an
    # estimate: 2^20 puts it in the same range as the AUI, but nothing in the
    # capture pins it down, so treat the vertical scale as arbitrary.
    "EX_LMS_FILTER_TIMEDOMAIN": ("i", 1 / 2 ** 20, "eq_time"),
    "EX_AUDIO_MOD_VECTOR": ("h", 0.01, "lissajous"),
}

# Channels read as raw integers regardless of what tx_spec says. The spec types
# TX_TRANSMITTER_TYPE as a "control" carrying Vpp at scale 1e-6 (its chanID
# 0x090d collides with an exciter calibration channel), but the wire value is a
# plain model index - 1 on this VS - and it selects the custom_range set.
RAW_CHANNELS = {"TX_TRANSMITTER_TYPE"}

# Text channels forwarded to the UI so nothing has to be hard-coded per site.
# tx_spec marks these type "String"; the wire value is text, optionally after a
# small binary prefix, padded with NUL or 0xFF.
TEXT_FIDS = {"TX_LAST_USED_PRESET_NAME", "TX_SET_FREQUENCY",
             "OAP_ACTIVE_PRESET_NAME"}

# Channels the AUI reads that tx_spec.xml does NOT define - base 0x00000000
# pseudo-channels carrying identity strings. The call sign (0x20) is the one the
# header needs; injected as a synthetic CONTROLLER channel so the UI can bind it
# by name. Others (0x120d station id, 0x1404 timezone) are left out until needed.
INFO_CHANNELS = {
    0x00000020: {"fid": "TX_CALL_SIGN", "label": "Call Sign", "kind": "text"},
}

# Tokens that must not be title-cased when prettifying a channel fID.
ACRONYMS = {"PA", "IPA", "MPX", "SCA", "RMS", "LVPS", "VSWR", "DC", "RF", "AGC",
            "DAC", "HD", "EQ", "LMS", "IBOC", "TCXO", "SNMP", "AUI", "PS", "V",
            "A", "W", "LR"}


# --------------------------------------------------------------------------
# tx_spec.xml
# --------------------------------------------------------------------------

class Spec:
    """Channel metadata from tx_spec.xml, keyed by 'DEVICE.CHANNEL_FID'."""

    def __init__(self, xml, labels=None):
        self.by_key = {}
        self.by_id = {}
        self.by_fid = {}
        labels = labels or {}
        device = None
        pattern = (r'<device\s+[^>]*fID="([A-Z_]+)"[^>]*>'
                   r'|<channel fID="([^"]+)"\s+chanID="([^"]+)"(.*?)</channel>')
        for m in re.finditer(pattern, xml, re.S):
            if m.group(1):
                device = m.group(1)
                continue
            if device not in DEVICE_BASE:
                continue
            body = m.group(4)
            chars = re.search(r"<characteristics([^>]*)>", body)
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', chars.group(1) if chars else ""))
            ctype = re.search(r"<type>(\w+)</type>", body)
            fid = m.group(2)
            entry = {
                "key": f"{device}.{fid}",
                "device": device,
                "fid": fid,
                "label": labels.get(fid) or prettify(fid),
                "id": DEVICE_BASE[device] | int(m.group(3), 16),
                "type": ctype.group(1) if ctype else "",
                "units": unescape_units(attrs.get("units", "")),
                "scale": float(attrs.get("scale", 1) or 1),
                "signed": attrs.get("signed", "true") != "false",
                "order": num(attrs.get("displayOrder")),
                # Thresholds are raw counts in the spec, same as the wire
                # values, so they carry the channel's scale too: PA current
                # rangeMax 15000 at scale 0.001 is the 15.0 A end of the bar.
                "zones": zone_set(attrs, attrs.get("scale", 1)),
                # Meter ranges vary by transmitter model. Each channel may carry
                # <custom_range id="N"> overrides selected by TX_TRANSMITTER_TYPE
                # (this VS reports type 1, giving the 0-200 W reflected scale the
                # AUI displays). Ship them all and let the client choose.
                "ranges": {m2.group(1): zone_set(
                               dict(re.findall(r'(\w+)="([^"]*)"', m2.group(2))),
                               attrs.get("scale", 1))
                           for m2 in re.finditer(
                               r'<custom_range\s+id="(\d+)"([^>]*)>', body)},
                "trueText": attrs.get("stringTrue"),
                "falseText": attrs.get("stringFalse"),
            }
            # The wire ID is the identity. A handful of fIDs are defined twice
            # with different chanIDs (alternate scalings, e.g. forward power as
            # W at 0x0100 and as kW at 0x0300); the first definition keeps the
            # plain name and later ones get their chanID appended, so both stay
            # addressable and the two lookup tables cannot disagree.
            if entry["id"] in self.by_id:
                continue
            if entry["key"] in self.by_key:
                entry["key"] += f"@{m.group(3)}"
                entry["label"] += f" ({entry['units']})"
            self.by_id[entry["id"]] = entry
            self.by_key[entry["key"]] = entry
            self.by_fid.setdefault(fid, entry)

        for cid, info in INFO_CHANNELS.items():
            entry = {"key": f"CONTROLLER.{info['fid']}", "device": "CONTROLLER",
                     "fid": info["fid"], "label": info["label"], "id": cid,
                     "type": "String", "units": "", "scale": 1, "signed": False,
                     "order": None, "zones": {}, "ranges": {},
                     "trueText": None, "falseText": None}
            self.by_id.setdefault(cid, entry)
            self.by_key.setdefault(entry["key"], entry)
            self.by_fid.setdefault(info["fid"], entry)

    def chartable(self):
        """Scalar channels worth showing as a number, bar or trend."""
        return [e for e in self.by_id.values()
                if e["type"] in ("meter", "number", "meterBool")
                or e["fid"] in RAW_CHANNELS]

    def texts(self):
        """String channels the header binds to (preset, call sign, frequency)."""
        return [e for e in self.by_id.values()
                if e["fid"] in TEXT_FIDS or e["id"] in INFO_CHANNELS]

    def arrays(self):
        return [e for e in self.by_id.values() if e["fid"] in ARRAY_CHANNELS]

    def monitored_ids(self):
        return ({e["id"] for e in self.chartable()} |
                {e["id"] for e in self.texts()} |
                {e["id"] for e in self.arrays()})


def num(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def zone_set(attrs, scale):
    return {k: scaled(attrs.get(k), scale) for k in
            ("rangeMin", "leftRed", "leftYellow", "rightYellow", "rightRed", "rangeMax")}


def scaled(text, scale):
    v = num(text)
    return None if v is None else v * (num(scale) or 1)


def prettify(fid):
    words = re.sub(r"^(TX|EX|CU|RA|OAP)_(METER_|ALARM_)?", "", fid).split("_")
    return " ".join(w if (w in ACRONYMS or any(c.isdigit() for c in w))
                    else w.capitalize() for w in words if w)


def unescape_units(text):
    return re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)


# Only ~43% of label keys sit next to their English text in the SWF string
# pool; the rest are stored in key runs with the translations elsewhere. These
# fill in names read directly off the AUI screenshots, and are limited to cases
# where the fID maps to the on-screen text unambiguously.
LABEL_OVERRIDES = {
    "TX_RF_ON_OFF": "RF On/Off",
    "TX_METER_FORWARD_RMS_POWER": "Forward Power",
    "TX_METER_REFLECTED_RMS_POWER": "Reflected Power",
    "TX_METER_PA_CURRENT_1": "PA 1 Current",
    "TX_METER_PA_CURRENT_2": "PA 2 Current",
    "TX_METER_PA_CURRENT_3": "PA 3 Current",
    "TX_METER_PA_CURRENT_4": "PA 4 Current",
    "TX_METER_PA_TEMP2": "Heatsink Temperature 2",
    "TX_METER_15V": "+15V", "TX_METER_MINUS_15V": "-15V",
    "TX_METER_5V": "+5V", "TX_METER_3_3V": "+3.3V",
    "TX_METER_1_8V": "+1.8V", "TX_METER_1_2V": "+1.2V",
    "TX_METER_VSWR": "VSWR", "TX_IPA_CURRENT": "IPA Current",
    "EX_SPECTRUM_AMPLITUDE": "Spectrum", "EX_LMS_FILTER_FREQDOMAIN": "EQ Frequency Response",
    "EX_LMS_FILTER_TIMEDOMAIN": "EQ Impulse Response", "EX_AUDIO_MOD_VECTOR": "Audio Mod Vector",
}


def load_labels():
    try:
        labels = json.load(open(os.path.join(HERE, "labels.json")))
    except (OSError, ValueError):
        labels = {}
    labels.update(LABEL_OVERRIDES)
    return labels


# The channel spec is served by the transmitter itself, so it never has to be
# distributed. A fetched copy is cached here so --demo/--replay work offline
# afterwards; the cache is gitignored alongside tx_spec.xml.
SPEC_URL = "http://{host}/bin/com/nautel/aui/assets/configs/vs/tx_spec.xml"
SPEC_CACHE = os.path.join(HERE, ".tx_spec.cache.xml")


def fetch_spec_xml(host, timeout=10):
    with urllib.request.urlopen(SPEC_URL.format(host=host), timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def load_spec(host=None, path=None):
    """Resolve tx_spec.xml, preferring an explicit file, then the transmitter,
    then a previously cached fetch. Fetched specs are cached for offline reuse."""
    labels = load_labels()
    if path:
        return Spec(open(path).read(), labels)
    if host:
        try:
            xml = fetch_spec_xml(host)
        except (urllib.error.URLError, OSError) as exc:
            if os.path.exists(SPEC_CACHE):
                print(f"spec fetch from {host} failed ({exc}); using cached copy",
                      file=sys.stderr)
                return Spec(open(SPEC_CACHE).read(), labels)
            raise SystemExit(f"could not fetch tx_spec.xml from {host}: {exc}")
        try:
            open(SPEC_CACHE, "w").write(xml)
        except OSError:
            pass  # cache is a convenience, not required
        return Spec(xml, labels)
    if os.path.exists(SPEC_CACHE):
        print(f"using cached tx_spec ({SPEC_CACHE})", file=sys.stderr)
        return Spec(open(SPEC_CACHE).read(), labels)
    raise SystemExit(
        "no tx_spec available. Pass --spec-host <transmitter> to fetch it once "
        "(it will be cached), or --spec <file> for a local copy.")


# --------------------------------------------------------------------------
# wire protocol
# --------------------------------------------------------------------------

def encode(msg_type, payload=b""):
    body = struct.pack("<HHB", len(payload) + 1, 0, msg_type) + payload
    out = bytearray([FLAG_START])
    for byte in body:
        if byte in ESCAPED:
            out += bytes([FLAG_ESC, ESCAPED[byte]])
        else:
            out.append(byte)
    out.append(FLAG_END)
    return bytes(out)


def id_list(channel_ids):
    return struct.pack("<H", len(channel_ids)) + b"".join(
        struct.pack("<I", i) for i in channel_ids)


class FrameReader:
    """Feed bytes in, get (msg_type, payload) frames out."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data):
        self.buf += data
        frames = []
        while True:
            start = self.buf.find(FLAG_START)
            if start < 0:
                self.buf.clear()
                break
            end = self.buf.find(FLAG_END, start + 1)
            if end < 0:
                del self.buf[:start]
                break
            dec = bytearray()
            i = start + 1
            while i < end:
                if self.buf[i] == FLAG_ESC:
                    dec.append((self.buf[i + 1] + 0xFD) & 0xFF)
                    i += 2
                else:
                    dec.append(self.buf[i])
                    i += 1
            del self.buf[:end + 1]
            if len(dec) >= 5:
                frames.append((dec[4], bytes(dec[5:])))
        return frames


def parse_values(payload):
    """Yield (channel_id, header, data) from a DATA message."""
    count = struct.unpack_from("<H", payload, 0)[0]
    off = 2
    for _ in range(count):
        if off + 8 > len(payload):
            return
        cid = struct.unpack_from("<I", payload, off)[0]
        total, hlen = struct.unpack_from("<HH", payload, off + 4)
        off += 8
        yield cid, payload[off:off + hlen], payload[off + hlen:off + total]
        off += total


def decode_sample(entry, header, data):
    """Return (timestamp, scaled_value) or None for non-scalar channels.

    A 5-byte header is the scalar timestamp (u32le unix seconds + u8
    hundredths); array channels carry 14/16/32-byte headers instead. Data
    widths other than 1/2/4 are timestamps or packed structs, not numbers.
    """
    if len(header) != 5 or len(data) not in (1, 2, 4):
        return None
    ts = struct.unpack("<I", header[:4])[0] + header[4] / 100.0
    raw = int.from_bytes(data, "little", signed=entry["signed"])
    return ts, raw * entry["scale"]


def decode_string(entry, header, data):
    """Return (timestamp, text) for a String channel.

    Values are text, optionally behind a short binary prefix (the call sign
    arrives as 0f 00 'K225DF' ff...), padded with NUL or 0xFF. Strip leading
    control bytes, then cut at the first padding byte. Frequency channels carry
    a scaled integer instead of text, so those are formatted numerically.
    """
    if len(header) != 5:
        return None
    ts = struct.unpack("<I", header[:4])[0] + header[4] / 100.0
    if entry["units"] == "MHz" and len(data) in (2, 4):  # TX_SET_FREQUENCY
        raw = int.from_bytes(data, "little", signed=False)
        return ts, f"{raw * entry['scale']:.2f} MHz"
    body = data.lstrip(bytes(range(0x20)))
    for pad in (b"\x00", b"\xff"):
        body = body.split(pad)[0]
    return ts, body.decode("latin1", "replace").strip()


def decode_array(entry, header, data):
    """Return {'values': [...], 'meta': {...}} for a plot channel."""
    fmt, scale, kind = ARRAY_CHANNELS[entry["fid"]]
    width = struct.calcsize("<" + fmt)
    count = len(data) // width
    values = [v * scale for v in struct.unpack_from(f"<{count}{fmt}", data)]
    meta = {"kind": kind}
    # The 32-byte spectrum header carries its own axis: centre frequency,
    # span and point count, all as little-endian int32.
    if len(header) >= 32:
        words = struct.unpack_from("<8i", header)
        meta.update(center=words[3], span=words[4], points=words[6])
    return {"values": values, "meta": meta}


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------

class DataSink:
    """Common decode path shared by the live and replay sources."""

    def __init__(self, spec, on_sample, on_array, on_text=None):
        self.spec = spec
        self.on_sample = on_sample
        self.on_array = on_array
        self.on_text = on_text or (lambda *a: None)
        self.allowed = spec.monitored_ids()
        self.text_ids = {e["id"] for e in spec.texts()}

    def handle(self, payload):
        for cid, header, data in parse_values(payload):
            entry = self.spec.by_id.get(cid)
            if not entry or cid not in self.allowed:
                continue
            if entry["fid"] in ARRAY_CHANNELS:
                try:
                    self.on_array(entry["key"], decode_array(entry, header, data))
                except struct.error:
                    pass
                continue
            if cid in self.text_ids:
                text = decode_string(entry, header, data)
                if text:
                    self.on_text(entry["key"], text[0], text[1])
                continue
            sample = decode_sample(entry, header, data)
            if sample:
                value = sample[1] / entry["scale"] if entry["fid"] in RAW_CHANNELS \
                    else sample[1]
                self.on_sample(entry["key"], sample[0], value)


class LiveSource(DataSink):
    """Talks to a real transmitter on TCP/3501."""

    def __init__(self, host, port, username, password, spec,
                 on_sample, on_array, on_text=None):
        super().__init__(spec, on_sample, on_array, on_text)
        self.host, self.port = host, port
        self.username = username.encode()
        self.password = (password or "").encode()
        self.writer = None
        self.subscribed = set()
        self.session_ack = None

    async def run(self):
        reader, self.writer = await asyncio.open_connection(self.host, self.port)
        frames = FrameReader()

        # Handshake as observed in password.pcapng stream 26 (the admin login
        # the server accepted): HELLO carries the credentials, LOGIN 0x00 lists
        # accounts, LOGIN 0x20 selects one by name. The password rides in HELLO,
        # NOT in the 0x20 select - the reverse was tried (stream 15) and drew no
        # reply from the server.
        self.writer.write(encode(MSG_HELLO, self._hello_payload()))
        self.writer.write(encode(MSG_LOGIN, b"\x00"))
        self.writer.write(encode(MSG_LOGIN,
                                 bytes([0x20, len(self.username)]) + self.username))
        await self.writer.drain()

        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            for msg_type, payload in frames.feed(chunk):
                if msg_type == MSG_DATA:
                    self.handle(payload)
                else:
                    self._handle_session(msg_type, payload)

    def _handle_session(self, msg_type, payload):
        """Report handshake progress.

        USER (0x14) frames come in three shapes, from the capture:
          00 <len> 00 00 01 <flag> <name><trailing>   account listing
          02 00 00 00 00 00                            end of listing
          20 <len> <name> <4 status bytes>            reply to our 0x20 select

        The 0x20 reply is only an acknowledgement that the account was selected:
        probing the live transmitter, a wrong password, an empty password, and
        even a nonexistent username all return status 00 00 00 00. So this
        confirms the frames are well-formed and the socket is usable, NOT that
        the credentials were validated - password enforcement happens elsewhere
        (likely gating privileged operations, which are not implemented here).
        """
        if msg_type == MSG_HELLO_ACK:
            print("hello acknowledged", file=sys.stderr)
        elif msg_type == MSG_USER and payload[:1] == b"\x00" and len(payload) > 6:
            # 00 | namelen | 00 00 | ?? | flag | name | trailing. Only the
            # length-prefixed name is solidly decoded; the trailing byte(s) are
            # an access indicator whose exact encoding is unconfirmed (single
            # digit for most accounts, "4703" for admin), so show them raw.
            n = payload[1]
            name = payload[6:6 + n].decode("latin1", "replace")
            trailing = payload[6 + n:].decode("latin1", "replace")
            print(f"  account: {name!r} (trailing {trailing!r})", file=sys.stderr)
        elif msg_type == MSG_USER and payload[:1] == b"\x20":
            n = payload[1]
            name = payload[2:2 + n].decode("latin1", "replace")
            status = payload[2 + n:]
            self.session_ack = not any(status)
            print(f"account {name!r} selected (ack status "
                  f"{status.hex(' ') or 'empty'}); note this does not verify "
                  f"the password", file=sys.stderr)

    def _hello_payload(self):
        """09 07 | u8 namelen | u8 pwlen | username | password.

        Confirmed against password.pcapng: the accepted admin login sent
        09 07 05 09 'admin' 'test12345' here, then selected the account with a
        bare LOGIN 0x20. With no password, pwlen is 0 and the frame matches the
        original Nautel capture byte-for-byte.
        """
        user, pw = self.username, self.password
        if len(user) > 255 or len(pw) > 255:
            raise ValueError("username/password too long for the u8 length field")
        return bytes([0x09, 0x07, len(user), len(pw)]) + user + pw

    async def subscribe(self, keys):
        """Add channels to the pushed set. The server's set is cumulative."""
        new = [self.spec.by_key[k]["id"] for k in keys
               if k in self.spec.by_key and k not in self.subscribed]
        if not new or not self.writer:
            return
        self.subscribed.update(k for k in keys if k in self.spec.by_key)
        self.writer.write(encode(MSG_SUBSCRIBE, id_list(new)))
        self.writer.write(encode(MSG_READ, id_list(new)))
        await self.writer.drain()


class ReplaySource(DataSink):
    """Replays the server side of a pcapng at its original pace."""

    def __init__(self, pcap, spec, on_sample, on_array, on_text=None, speed=1.0):
        super().__init__(spec, on_sample, on_array, on_text)
        self.pcap, self.speed = pcap, speed

    def _packets(self):
        out = subprocess.run(
            ["tshark", "-r", self.pcap, "-Y", "tcp.srcport==3501 && tcp.len>0",
             "-T", "fields", "-e", "frame.time_relative", "-e", "tcp.payload"],
            capture_output=True, text=True, check=True).stdout
        packets = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[1]:
                packets.append((float(parts[0]), bytes.fromhex(parts[1].replace(":", ""))))
        return packets

    async def run(self):
        packets = self._packets()
        if not packets:
            raise SystemExit("no TCP/3501 payload found in capture")
        print(f"replaying {len(packets)} packets at {self.speed}x", file=sys.stderr)
        while True:
            frames = FrameReader()
            base, started = packets[0][0], time.monotonic()
            for rel, payload in packets:
                delay = (rel - base) / self.speed - (time.monotonic() - started)
                if delay > 0:
                    await asyncio.sleep(delay)
                for msg_type, body in frames.feed(payload):
                    if msg_type == MSG_DATA:
                        self.handle(body)

    async def subscribe(self, keys):
        return  # the capture dictates what arrives


class DemoSource:
    """Synthetic data so the UI can be developed with nothing attached.

    Anchored to the values in the reference screenshots; everything else
    wanders inside its tx_spec range.
    """

    ANCHORS = {
        "TX_METER_FORWARD_RMS_POWER": 686.0, "TX_METER_REFLECTED_RMS_POWER": 2.58,
        "TX_METER_PREAMP_CURRENT": 0.07, "TX_IPA_CURRENT": 2.54,
        "TX_METER_PA_CURRENT_1": 6.99, "TX_METER_PA_CURRENT_2": 7.95,
        "TX_METER_PA_CURRENT_3": 8.02, "TX_METER_PA_CURRENT_4": 6.94,
        "TX_METER_HEATSINK_TEMPERATURE": 34.0, "TX_METER_PA_TEMP2": 34.6,
        "TX_METER_48V": 48.2, "TX_METER_15V": 15.0, "TX_METER_MINUS_15V": -15.4,
        "TX_METER_5V": 4.98, "TX_METER_3_3V": 3.28,
        "TX_METER_TOTAL_PA_CURRENT": 29.9, "TX_METER_VSWR": 1.13,
        "TX_METER_FINAL_REJECT_POWER": 0.0,
    }

    # Discrete channels: reported exactly, never jittered. TX_TRANSMITTER_TYPE
    # matters beyond display - it selects which custom_range set applies.
    EXACT = {"TX_TRANSMITTER_TYPE": 1, "TX_RF_ON_OFF": 1, "TX_LOCAL_REMOTE": 1,
             "TX_ACTIVE_EXCITER": 0, "TX_NUMBER_OF_POWER_SUPPLIES": 4,
             "TX_NUMBER_OF_FANS": 3}

    def __init__(self, spec, on_sample, on_array, on_text=None):
        self.spec, self.on_sample, self.on_array = spec, on_sample, on_array
        self.on_text = on_text or (lambda *a: None)

    async def run(self):
        phase = 0.0
        while True:
            now = time.time()
            for entry in self.spec.chartable():
                if entry["fid"] in self.EXACT:
                    self.on_sample(entry["key"], now, self.EXACT[entry["fid"]])
                    continue
                if entry["type"] == "meterBool":
                    self.on_sample(entry["key"], now, 0)
                    continue
                base = self.ANCHORS.get(entry["fid"])
                if base is None:
                    lo = entry["zones"].get("rangeMin") or 0.0
                    hi = entry["zones"].get("rangeMax") or 1.0
                    base = lo + (hi - lo) * 0.45
                jitter = abs(base) * 0.01 or 0.01
                floor = entry["zones"].get("rangeMin")
                v = base + random.uniform(-jitter, jitter)
                if floor is not None:
                    v = max(floor, v)
                self.on_sample(entry["key"], now, round(v, 3))
            self._text(now)
            self._arrays(phase)
            phase += 0.15
            await asyncio.sleep(0.5)

    # Header strings for --demo. Deliberately generic placeholders, not a real
    # station's identity - live/replay fill these from the transmitter.
    TEXT = {"TX_LAST_USED_PRESET_NAME": "DEMO 90.1 1kW",
            "TX_SET_FREQUENCY": "90.10 MHz", "TX_CALL_SIGN": "DEMO-FM",
            "OAP_ACTIVE_PRESET_NAME": "DEMO PRESET"}

    def _text(self, now):
        for fid, value in self.TEXT.items():
            entry = self.spec.by_fid.get(fid)
            if entry:
                self.on_text(entry["key"], now, value)

    def _arrays(self, phase):
        key = self._key("EX_SPECTRUM_AMPLITUDE")
        if key:
            points = 1001
            values = []
            for i in range(points):
                off = (i - points / 2) / (points / 2)          # -1 .. +1
                carrier = -8 - 60 * min(1.0, (abs(off) / 0.18) ** 2)
                values.append(round(max(-100.0, carrier + random.uniform(-1.5, 1.5)), 2))
            self.on_array(key, {"values": values,
                                "meta": {"kind": "spectrum", "center": 92900000,
                                         "span": 1000000, "points": points}})
        key = self._key("EX_LMS_FILTER_FREQDOMAIN")
        if key:
            n = 1024
            values = [round(-10.2 * max(0.0, (abs(i - n / 2) / (n / 2) * 1.35) ** 6)
                            + random.uniform(-0.02, 0.02), 2) for i in range(n)]
            self.on_array(key, {"values": values, "meta": {"kind": "eq_freq"}})
        key = self._key("EX_LMS_FILTER_TIMEDOMAIN")
        if key:
            values = []
            for tap in range(16):
                x = (tap - 7.5) * 0.9
                sinc = 246.0 if abs(x) < 1e-6 else 246.0 * math.sin(x) / x
                values += [round(sinc, 2), round(sinc * 0.06, 2)]
            self.on_array(key, {"values": values, "meta": {"kind": "eq_time"}})
        key = self._key("EX_AUDIO_MOD_VECTOR")
        if key:
            values = []
            for i in range(17):
                a = phase + i * 0.37
                values += [round(70 * math.sin(a), 2), round(70 * math.sin(a * 1.03), 2)]
            self.on_array(key, {"values": values, "meta": {"kind": "lissajous"}})

    def _key(self, fid):
        entry = self.spec.by_fid.get(fid)
        return entry["key"] if entry else None

    async def subscribe(self, keys):
        return


# --------------------------------------------------------------------------
# HTTP + WebSocket (no third-party dependencies)
# --------------------------------------------------------------------------

class Server:
    def __init__(self, spec):
        self.spec = spec
        self.source = None
        self.clients = set()

    def _push(self, obj):
        if not self.clients:
            return
        msg = ws_text(json.dumps(obj))
        for writer in list(self.clients):
            try:
                writer.write(msg)
            except Exception:
                self.clients.discard(writer)

    def broadcast(self, key, ts, value):
        self._push({"k": key, "t": ts, "v": value})

    def broadcast_array(self, key, payload):
        self._push({"k": key, "a": payload["values"], "m": payload["meta"]})

    def broadcast_text(self, key, ts, text):
        self._push({"k": key, "t": ts, "s": text})

    def channel_json(self):
        out = []
        for entry in self.spec.chartable() + self.spec.arrays() + self.spec.texts():
            out.append({k: entry[k] for k in
                        ("key", "device", "fid", "label", "units", "type",
                         "zones", "ranges", "order", "trueText", "falseText")})
        return sorted(out, key=lambda e: (e["device"], e["order"] or 1e9, e["label"]))

    async def handle(self, reader, writer):
        try:
            request = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        head = request.decode("latin1")
        path = head.split(" ")[1] if " " in head else "/"
        key = re.search(r"Sec-WebSocket-Key:\s*(\S+)", head, re.I)

        if key and "upgrade" in head.lower():
            await self._websocket(reader, writer, key.group(1))
            return

        if path.startswith("/api/channels"):
            self._respond(writer, json.dumps(self.channel_json()).encode(),
                          "application/json")
        else:
            page = "chart.html" if path.startswith("/chart") else "aui.html"
            try:
                self._respond(writer, open(os.path.join(HERE, page), "rb").read(),
                              "text/html; charset=utf-8")
            except FileNotFoundError:
                self._respond(writer, f"{page} missing".encode(),
                              "text/plain", "404 Not Found")
        await writer.drain()
        writer.close()

    def _respond(self, writer, body, ctype, status="200 OK"):
        writer.write(f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n"
                     f"Content-Length: {len(body)}\r\n"
                     f"Cache-Control: no-store\r\nConnection: close\r\n\r\n".encode())
        writer.write(body)

    async def _websocket(self, reader, writer, key):
        accept = base64.b64encode(
            hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        await writer.drain()
        self.clients.add(writer)
        try:
            while True:
                msg = await ws_read(reader)
                if msg is None:
                    break
                try:
                    request = json.loads(msg)
                except ValueError:
                    continue
                if request.get("op") == "subscribe":
                    await self.source.subscribe(request.get("keys", []))
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            self.clients.discard(writer)
            writer.close()


def ws_text(text):
    data = text.encode()
    if len(data) < 126:
        header = struct.pack("!BB", 0x81, len(data))
    elif len(data) < 1 << 16:
        header = struct.pack("!BBH", 0x81, 126, len(data))
    else:
        header = struct.pack("!BBQ", 0x81, 127, len(data))
    return header + data


async def ws_read(reader):
    head = await reader.readexactly(2)
    opcode = head[0] & 0x0F
    masked = head[1] & 0x80
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if opcode == 0x8:
        return None
    return payload.decode("utf-8", "replace") if opcode == 0x1 else ""


# --------------------------------------------------------------------------

async def probe(args):
    """Handshake only: prove credentials work before wiring up the dashboard."""
    print(f"connecting to {args.host}:{args.port} as {args.user!r} "
          f"({'with' if args.password else 'no'} password)", file=sys.stderr)
    spec = Spec("")  # no channel metadata needed to test a login
    source = LiveSource(args.host, args.port, args.user, args.password, spec,
                        lambda *a: None, lambda *a: None)
    data = []
    source.on_sample = lambda *a: data.append(a)
    try:
        await asyncio.wait_for(source.run(), timeout=args.probe_seconds)
    except asyncio.TimeoutError:
        pass
    except OSError as exc:
        print(f"connection failed: {exc}", file=sys.stderr)
        return
    if source.session_ack:
        print("RESULT: handshake ok, account selected. NOTE: the transmitter "
              "acknowledges any credentials at this layer - a wrong or empty "
              "password is not rejected here - so this confirms the socket "
              "works, not that the password is correct.", file=sys.stderr)
    else:
        print("RESULT: no account-select reply seen. The server may have "
              "closed the connection on a malformed frame.", file=sys.stderr)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="transmitter address (live mode)")
    ap.add_argument("--port", type=int, default=3501)
    ap.add_argument("--user", default="Nautel", help="AUI account name")
    ap.add_argument("--password", default=os.environ.get("NAUTEL_PASSWORD"),
                    help="AUI password; defaults to $NAUTEL_PASSWORD. Note that "
                         "anything passed here is visible to other users via ps")
    ap.add_argument("--replay", help="pcapng to replay instead of connecting")
    ap.add_argument("--demo", action="store_true", help="synthetic data")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    ap.add_argument("--spec", help="local tx_spec.xml file (optional)")
    ap.add_argument("--spec-host", help="fetch tx_spec.xml over HTTP from this "
                    "transmitter, for --demo/--replay (cached for offline reuse)")
    ap.add_argument("--listen", type=int, default=8531)
    ap.add_argument("--probe", action="store_true",
                    help="run the handshake against --host, report the result, exit")
    ap.add_argument("--probe-seconds", type=float, default=8.0)
    args = ap.parse_args()

    if not (args.host or args.replay or args.demo):
        ap.error("need --host, --replay or --demo")

    if args.probe:
        if not args.host:
            ap.error("--probe needs --host")
        return await probe(args)

    # Live mode fetches the spec from the connected transmitter; otherwise take
    # it from --spec, --spec-host, or a prior cached fetch (see load_spec).
    spec = load_spec(host=args.host or args.spec_host, path=args.spec)
    print(f"{len(spec.by_id)} channels, {len(spec.chartable())} scalar, "
          f"{len(spec.arrays())} array", file=sys.stderr)

    server = Server(spec)
    if args.demo:
        server.source = DemoSource(spec, server.broadcast, server.broadcast_array,
                                   server.broadcast_text)
    elif args.replay:
        server.source = ReplaySource(args.replay, spec, server.broadcast,
                                     server.broadcast_array, server.broadcast_text,
                                     args.speed)
    else:
        server.source = LiveSource(args.host, args.port, args.user, args.password,
                                   spec, server.broadcast, server.broadcast_array,
                                   server.broadcast_text)

    http = await asyncio.start_server(server.handle, "127.0.0.1", args.listen)
    print(f"open http://localhost:{args.listen}/", file=sys.stderr)
    await asyncio.gather(http.serve_forever(), server.source.run())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
