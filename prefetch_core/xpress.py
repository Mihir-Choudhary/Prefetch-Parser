"""XPRESS Huffman (LZ77 + Huffman) decompressor - pure Python, no dependencies.

Implemented directly from the [MS-XCA] "LZ77+Huffman Decompression Algorithm Details"
pseudocode:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/26db8e62-bbd8-472c-a09e-623f6de10f0b

This is what lets Windows 10/11 prefetch (MAM containers) be parsed off-Windows, where
ntdll!RtlDecompressBufferEx does not exist.

Format: a stream of blocks, each producing up to 64 KB of output. Each block begins with a
256-byte Huffman table (512 symbols, 4 bits of code length each, low nibble = even symbol),
followed by a bitstream. Symbols 0-255 are literals, 256 is EOF, 257-511 encode an LZ77
match as (offset_bit_length << 4) | length_nibble.

Three details the spec is explicit about and that are easy to get wrong:
  * Match LENGTH is decoded before match OFFSET. The length's extra bytes come off the same
    input pointer the bitstream refills from, so the order changes what gets read.
  * The long-length escape is a byte equal to 255, and the trailing "+ 15" applies on both
    the short and the escaped path.
  * The match copy must be byte-at-a-time: length may exceed offset (e.g. "aaaaaa" encodes
    as literal 'a' + match offset=1 length=5).
"""

import struct

_TABLE_BITS = 15
_TABLE_SIZE = 1 << _TABLE_BITS


class InvalidCompressedData(ValueError):
    """The input is not valid XPRESS Huffman data."""


def _build_decoding_table(source, pos):
    """[MS-XCA] table construction. Returns (symbol_table, bit_length_table).

    Each symbol of bit length X occupies 2^(15-X) consecutive entries, ordered by
    (bit length, symbol value). A complete code fills exactly 2^15 entries - anything
    else means the data is corrupt, which makes this self-validating.
    """
    lengths = []
    for i in range(256):
        b = source[pos + i]
        lengths.append(b & 0x0F)
        lengths.append(b >> 4)

    # Plain lists filled by slice assignment. The obvious transcription of the spec writes each
    # of the 32,768 entries individually with struct.pack_into, which costs ~2.6M calls per 40
    # files and dominated the whole parse. A symbol's entries are contiguous and identical, so
    # one slice assignment per symbol replaces `count` separate writes.
    symbols = [0] * _TABLE_SIZE
    bitlens = bytearray(_TABLE_SIZE)
    entry = 0
    for bit_length in range(1, 16):
        count = 1 << (15 - bit_length)
        for symbol in range(512):
            if lengths[symbol] != bit_length:
                continue
            end = entry + count
            if end > _TABLE_SIZE:
                raise InvalidCompressedData("Huffman table overflows 2^15 entries")
            symbols[entry:end] = [symbol] * count
            bitlens[entry:end] = bytes([bit_length]) * count
            entry = end

    if entry != _TABLE_SIZE:
        raise InvalidCompressedData(
            f"incomplete Huffman code: {entry} of {_TABLE_SIZE} table entries")

    return symbols, bitlens


def decompress(data, out_size, max_output=None):
    """Decompress `data`, producing exactly `out_size` bytes.

    `max_output` refuses a container that declares more than the caller is willing to hold. The
    declared size is attacker-controlled and a valid stream can expand roughly 256x, so without
    a ceiling "parse this file" can allocate gigabytes before failing.
    """
    if max_output is not None and out_size > max_output:
        raise InvalidCompressedData(
            f"declared output {out_size:,} bytes exceeds the {max_output:,} byte ceiling")
    out = bytearray()
    pos = 0
    n = len(data)


    while len(out) < out_size:
        if pos + 256 > n:
            raise InvalidCompressedData("truncated: no room for a Huffman table")

        symbols, bitlens = _build_decoding_table(data, pos)
        pos += 256

        # 32-bit register holding at least the next 16 bits of input
        if pos + 4 > n:
            raise InvalidCompressedData("truncated: no room for the bit register")
        next_bits = (struct.unpack_from("<H", data, pos)[0] << 16) | \
                    struct.unpack_from("<H", data, pos + 2)[0]
        pos += 4
        extra_bits = 16

        block_end = len(out) + 65536

        while len(out) < block_end and len(out) < out_size:
            index = next_bits >> (32 - _TABLE_BITS)
            symbol = symbols[index]          # plain list; see _build_decoding_table
            bit_length = bitlens[index]

            next_bits = (next_bits << bit_length) & 0xFFFFFFFF
            extra_bits -= bit_length
            if extra_bits < 0:
                if pos + 2 > n:
                    raise InvalidCompressedData("truncated bitstream")
                next_bits |= struct.unpack_from("<H", data, pos)[0] << (-extra_bits)
                extra_bits += 16
                pos += 2

            if symbol < 256:
                out.append(symbol)
                continue

            # Symbol 256 is EOF *only* when the expected output has already been written.
            # Otherwise the spec falls straight through to the match path, where it decodes
            # as length nibble 0 / offset bit length 0 -> a 3-byte match at offset 1.
            # Skipping it instead loses 3 bytes and desynchronizes the stream.
            if symbol == 256 and len(out) >= out_size:
                return bytes(out[:out_size])

            symbol -= 256
            match_length = symbol % 16
            offset_bit_length = symbol // 16

            # LENGTH FIRST: its extra bytes come off the same pointer the register refills
            # from, so doing this after the offset would read the wrong bytes.
            if match_length == 15:
                if pos >= n:
                    raise InvalidCompressedData("truncated match length")
                match_length = data[pos]
                pos += 1
                if match_length == 255:
                    if pos + 2 > n:
                        raise InvalidCompressedData("truncated match length")
                    match_length = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                    if match_length == 0:
                        # Not in the spec's decoder pseudocode, but the encoder emits it:
                        # a zero u16 means the real length follows as a u32.
                        if pos + 4 > n:
                            raise InvalidCompressedData("truncated match length")
                        match_length = struct.unpack_from("<I", data, pos)[0]
                        pos += 4
                    if match_length < 15:
                        raise InvalidCompressedData("corrupt long match length")
                    match_length -= 15
                match_length += 15
            match_length += 3

            match_offset = next_bits >> (32 - offset_bit_length) if offset_bit_length else 0
            match_offset += 1 << offset_bit_length
            next_bits = (next_bits << offset_bit_length) & 0xFFFFFFFF
            extra_bits -= offset_bit_length
            if extra_bits < 0:
                if pos + 2 > n:
                    raise InvalidCompressedData("truncated bitstream")
                next_bits |= struct.unpack_from("<H", data, pos)[0] << (-extra_bits)
                extra_bits += 16
                pos += 2

            if match_offset > len(out):
                raise InvalidCompressedData(
                    f"match offset {match_offset} exceeds output {len(out)}")

            # byte at a time: match_length may exceed match_offset
            start = len(out) - match_offset
            for k in range(match_length):
                out.append(out[start + k])

    return bytes(out[:out_size])


def decompress_mam(raw):
    """Decompress a MAM container (Win10/11 prefetch, ResPri*.ebd, ...).

    Layout: 'MAM' + flag byte, uint32 uncompressed size, then the compressed stream.
    Bit 7 of the flag byte inserts an extra 4-byte field before the payload.
    """
    if raw[:3] != b"MAM":
        raise InvalidCompressedData("not a MAM container")
    flags = raw[3]
    out_size = struct.unpack_from("<I", raw, 4)[0]
    payload = 12 if (flags & 0x80) else 8
    return decompress(raw[payload:], out_size)


PFB_MAGIC = b"PfB\xe3"
_PFB_CHUNK = 65536


def decompress_pfb(raw, max_output=None):
    """Decompress a ReadyBoot `PfB` container (`Trace*.fx`, `rblayout.xin`).

    Unlike MAM, this is not one XPRESS stream - it is a *chain* of independent 64 KB XPRESS
    Huffman chunks, which is why every whole-stream decode attempt failed:

        u32  magic 0xE3426650 ('PfB\\xe3')
        u32  total uncompressed size
        u32  compressed length of chunk 0
             chunk 0 data
             u32  unidentified (high entropy; not length or count)
             u32  compressed length of chunk 1
             chunk 1 data
             ...

    Each chunk decompresses to exactly 64 KB (the last to the remainder) and resets the LZ77
    history, so chunks are decoded independently rather than against a shared window.

    See docs/readyboot-format.md for how this was derived and how it was verified: every chunk
    start in the corpus lands on a Kraft-complete Huffman table, and all six files decode to
    exactly their declared size.
    """
    if raw[:4] != PFB_MAGIC:
        raise InvalidCompressedData("not a PfB container")
    if len(raw) < 12:
        raise InvalidCompressedData("truncated PfB header")
    _magic, total, chunk_len = struct.unpack_from("<3I", raw, 0)
    if total == 0:
        # The chunk loop would exit immediately and report a clean empty decode. Reporting
        # "decoded, 0 names" for a corrupt trace is worse than reporting a problem: it tells an
        # analyst the boot touched nothing.
        raise InvalidCompressedData("declares zero uncompressed bytes")
    if max_output is not None and total > max_output:
        raise InvalidCompressedData(
            f"declared output {total:,} bytes exceeds the {max_output:,} byte ceiling")

    out = bytearray()
    pos = 12
    n = len(raw)
    while len(out) < total:
        # A zero-length chunk would leave `pos` stationary and spin this loop forever on a
        # crafted file; every other guard here is bounds, but this one is liveness.
        if chunk_len == 0:
            raise InvalidCompressedData("zero-length chunk")
        want = min(_PFB_CHUNK, total - len(out))
        final = want == total - len(out)
        if pos + chunk_len > n:
            # The trailer that precedes the LAST chunk does not hold a valid length - the
            # observed values are wild (4,097,071,853 on Trace2.fx) and differ per file, so the
            # field is simply undefined once there is no next chunk to describe. The final
            # chunk runs to EOF. Clamping is safe; accepting the bogus length is not, and a
            # naive `raw[pos:pos+chunk_len]` hides the whole problem because Python slicing
            # silently stops at the end of the buffer.
            if not final:
                raise InvalidCompressedData(
                    f"chunk at {pos} claims {chunk_len:,} bytes, past the {n:,} byte file")
            chunk_len = n - pos
        produced = decompress(raw[pos:pos + chunk_len], want)
        if len(produced) != want:
            raise InvalidCompressedData(
                f"chunk at {pos} produced {len(produced):,} bytes, expected {want:,}")
        out += produced
        pos += chunk_len
        if len(out) >= total:
            break
        if pos + 8 > n:
            raise InvalidCompressedData("truncated inter-chunk trailer")
        _unidentified, chunk_len = struct.unpack_from("<2I", raw, pos)
        pos += 8
    return bytes(out)
