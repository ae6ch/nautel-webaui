# Nautel AUI protocol (TCP/3501)

Reference for the binary protocol spoken by the Nautel AUI, the Flash control interface on Nautel FM
transmitters (reference unit: a VS-series, `NAPE83`). The AUI is a SWF served over HTTP; it opens a
raw TCP socket to port **3501** for live telemetry.

Everything here was reverse-engineered from packet captures plus the transmitter's own config files
(`tx_spec.xml`) and Flash app — there is no vendor documentation. Where a detail is inferred rather
than confirmed, it says so.

## Ports

| Port | Purpose |
|------|---------|
| 80   | HTTP — serves the SWF and config XML (`tx_spec.xml` and friends) |
| 843  | Flash socket-policy server |
| 3501 | The binary telemetry/control socket described here |

## Framing

```
FF | u16le length | u16 reserved(0) | u8 msg_type | payload | FE
```

`length` counts `payload + 1` — it includes the trailing `FE`.

### Byte stuffing — the sharpest trap

`FD` escapes a literal `FD`/`FE`/`FF` in the body as `FD 00`/`FD 01`/`FD 02`; the byte after `FD`
carries *(original − 0xFD)*.

This is easy to get subtly wrong. Framing and length checks pass identically under a wrong escape
offset, because the *number* of escape bytes is unchanged — so a bad mapping validates cleanly and
then silently corrupts any value containing `0xFE` or `0xFF`. It was pinned down against
`EX_SPECTRUM_FREQUENCY`, whose payload is a known linear ramp (−500000 Hz in 1000 Hz steps over 1001
points). **Verify escaping against real decoded content like that ramp, not against frame lengths.**

## Message types

Client → server:

| Type | Name | Payload |
|------|------|---------|
| `0x00` | READ | one-shot read: `u16le count` + N × 4-byte channel IDs |
| `0x03` | SUBSCRIBE | add channel IDs to the pushed set (same id-list shape) |
| `0x05` | SUBSCRIBE_ARRAY | subscribe to array channels (spectrum, etc.) |
| `0x09` | HELLO | see handshake |
| `0x13` | LOGIN | see handshake |

Server → client:

| Type | Name | Notes |
|------|------|-------|
| `0x0B` | DATA | channel values, see below |
| `0x0D` | SUBSCRIPTION | echoes the whole cumulative subscription set |
| `0x0F` | HELLO_ACK | |
| `0x14` | USER | account listing and login reply |

READ / SUBSCRIBE / SUBSCRIPTION payloads all share the shape `u16le count` followed by that many
4-byte channel IDs. Subscriptions are cumulative — the server re-echoes the full set after each add.

## DATA values

A DATA message is `u16le count`, then that many entries. Each entry is:

```
channelID(4) | u16le total_len | u16le header_len | header | data
```

- **`header_len == 5`** → scalar. Header is `u32le` Unix seconds + `u8` hundredths of a second. `data`
  is a little-endian integer, scaled by the channel's `scale` attribute from `tx_spec.xml`.
- **`header_len` of 14 / 16 / 32** → array channel (spectrum, EQ, modulation vector). The 32-byte
  spectrum header carries centre frequency, span and point count as `int32`, which is where the
  plot's frequency axis comes from.

### Array channels

| Channel | Element | Scale | Notes |
|---------|---------|-------|-------|
| `EX_SPECTRUM_AMPLITUDE` | `int16` | 0.01 dB | RF spectrum |
| `EX_SPECTRUM_MASK_AMPLITUDE` | `int16` | 0.01 dB | regulatory mask overlay |
| `EX_LMS_FILTER_FREQDOMAIN` | `int16` | 0.01 dB | EQ frequency response |
| `EX_LMS_FILTER_TIMEDOMAIN` | `int32` | *see note* | 16 taps, interleaved (real, imag) |
| `EX_AUDIO_MOD_VECTOR` | `int16` | 0.01 | L/R Lissajous; its peak is the FM modulation % |

The impulse-response tap count and interleave are confirmed by the shape (a clean impulse decaying to
zero at both edges) and the AUI's 0–15 tap axis, but **its amplitude divisor (≈2²⁰) is an unverified
estimate** — treat the vertical scale as arbitrary.

The FM modulation percentage shown in the header is not a scalar channel at all: it is the peak
magnitude of `EX_AUDIO_MOD_VECTOR`, which is pushed several times a second for exactly this purpose.

## Handshake and login

Confirmed live and against a capture (`password.pcapng` stream 26, an accepted `admin` login):

1. **HELLO** `0x09` — `09 07 | u8 namelen | u8 pwlen | username | password`. **The password rides in
   the HELLO frame**, not the login select. With no password, `pwlen` is 0.
2. **LOGIN** `0x13` payload `00` — asks the server to list accounts (returned as `0x14` USER frames).
3. **LOGIN** `0x13` payload `0x20 | u8 namelen | username` — selects the account **by name only, no
   password**.

The server replies with a `0x14` USER frame `20 <namelen> <name> <4 status bytes>`.

### The login reply does not validate the password

Status `00 00 00 00` looks like "accepted", but it only acknowledges that the account was *selected*.
Probing a live transmitter, a wrong password, an empty password, and even a nonexistent username all
return `00 00 00 00`. So the reply confirms the socket is usable and the frames are well-formed — not
that the credentials are correct. Password enforcement appears to gate privileged operations, which
are not part of this (read-only) implementation.

Two login styles appear in the wild and only one works: putting the password in the LOGIN `0x20`
select draws no reply (a dead end), while putting it in HELLO gets the acknowledgement. The failed
style passes every static/length check and only fails against live hardware — verify against a real
accepted login, not a plausible-looking frame.

## Reads only

The captures contain no write operations, so the command/set encoding is unknown and nothing here can
change transmitter state. Adding control would require capturing an AUI session that actually changes
a setting (a preset, RF on/off), then working out the write frames.

## Channel model

A channel ID is `deviceBase | chanID`, little-endian on the wire. Device bases come from `tx_spec.xml`
`<device>` attributes: base = parent base + `offsetFromParent`, with siblings stepping by
`offsetFromSibling`. Observed live: `0x01000000` Controller, `0x04010000` Exciter, `0x040B0000` Orban
audio processor. The spec also defines an HD Exciter and Exgine, which a given transmitter may not
physically have.

`tx_spec.xml` is the whole data model — units, scaling, signedness, display order, alarm thresholds.
Several details are load-bearing:

- **The wire ID is the identity, not the fID.** A handful of fIDs are defined twice with different
  chanIDs as alternate scalings (e.g. forward power as W at `0x0100` and kW at `0x0300`). Keying by
  name silently picks the wrong scale — key by the numeric ID.
- **Thresholds are raw counts**, the same as wire values, so they carry the channel's `scale`. PA
  current `rangeMax` 15000 at scale 0.001 is the 15.0 A end of the bar.
- **Meter ranges are per-model.** Channels carry `<custom_range id="N">` overrides selected by
  `TX_TRANSMITTER_TYPE`. This VS reports type **1**, which yields the 0–200 W reflected-power scale
  the AUI shows rather than the 40 W default.
- **`TX_TRANSMITTER_TYPE` must be read unscaled.** The spec types it as a `control` carrying Vpp at
  scale 1e-6 (its chanID `0x090d` collides with an exciter calibration channel), but the wire value
  is a plain integer model index.

### Identity strings

The header identity — call sign, preset name, carrier frequency, active exciter — all come from the
transmitter, so the same UI works for any unit. Preset and frequency are `String`-typed channels;
their wire value is text, optionally behind a short binary prefix and padded with NUL or `0xFF`.

The **call sign is not in `tx_spec.xml`.** It arrives on base-`0x00000000` pseudo-channel `0x20` as
`0f 00 'K225DF' ff...`. Other base-0 pseudo-channels exist too (`0x120d` station id, `0x1404`
timezone).

## Labels

`tx_spec.xml` names channels by fID (e.g. `TX_METER_FORWARD_RMS_POWER`), not by their human label. The
labels live in the Flash app's string pool: the SWF (`AUILoader.php` from the HTTP export) is
`CWS`-compressed — zlib-decompress from byte 8 — and in its ABC constant pool each label key sits
immediately before its English text. About 43% of keys resolve by that adjacency; the rest are stored
in key runs with the translations elsewhere. The remainder fall back to a prettified fID or a small
hand-verified override table.
