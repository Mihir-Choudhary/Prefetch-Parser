"""MAM container detection and decompression.

Every Win10/11 prefetch file is a `MAM` container holding XPRESS-Huffman-compressed data.
PECmd asks Windows to decompress it via `ntdll!RtlDecompressBufferEx`, which is why it cannot
run off Windows at all.

Two decompressors are available here and they must produce byte-identical output:

  * `ntdll`  - the OS call, when it is present and usable.
  * `pure`   - `xpress.py`, written from [MS-XCA]. Decompresses all 642 MAM files in the
               corpora with zero failures.

**Selection is by capability probe, not an OS check.** `ntdll` can be blocked on hardened
Windows and is present under Wine, so `platform.system() == "Windows"` answers the wrong
question. Resolve the symbol and branch on whether it actually worked.
"""

from __future__ import annotations

import ctypes
import struct
from typing import Callable

from . import xpress
from .limits import MAX_DECOMPRESSED_BYTES
from .errors import PrefetchError, Stage

MAM_MAGIC = b"MAM"
COMPRESSION_FORMAT_XPRESS_HUFF = 4


def _probe_ntdll() -> Callable[[bytes, int], bytes] | None:
    """Return an ntdll-backed decompressor, or None if it is unavailable for any reason."""
    try:
        ntdll = ctypes.WinDLL("ntdll")           # type: ignore[attr-defined]
        rtl = ntdll.RtlDecompressBufferEx
        get_size = ntdll.RtlGetCompressionWorkSpaceSize
    except (AttributeError, OSError):
        return None

    def decompress(payload: bytes, out_size: int) -> bytes:
        workspace_size = ctypes.c_ulong(0)
        fragment_size = ctypes.c_ulong(0)
        status = get_size(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
            ctypes.byref(workspace_size),
            ctypes.byref(fragment_size),
        )
        if status != 0:
            raise PrefetchError(Stage.CONTAINER, f"RtlGetCompressionWorkSpaceSize: 0x{status:08X}")
        out = ctypes.create_string_buffer(out_size)
        workspace = ctypes.create_string_buffer(workspace_size.value)
        written = ctypes.c_ulong(0)
        status = rtl(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
            out, ctypes.c_ulong(out_size),
            ctypes.c_char_p(payload), ctypes.c_ulong(len(payload)),
            ctypes.byref(written), workspace,
        )
        if status != 0:
            raise PrefetchError(Stage.CONTAINER, f"RtlDecompressBufferEx: 0x{status:08X}")
        return out.raw[: written.value]

    return decompress


_NTDLL = _probe_ntdll()


def available_decompressors() -> list[str]:
    return (["ntdll"] if _NTDLL else []) + ["pure"]


def is_container(head: bytes) -> bool:
    return head[:3] == MAM_MAGIC


def parse_header(raw: bytes) -> tuple[int, int]:
    """Return (payload_offset, uncompressed_size) for a MAM container.

    Layout is `'MAM' | flags | u32 uncompressed_size | [u32 extra] | payload`.

    Bit 7 of the flags byte adds a 4-byte field, moving the payload from +8 to **+12**. That
    was an open question for a while because no prefetch file sets it; it is confirmed by the
    two `ResPri*.ebd` SuperFetch databases, which decompress correctly at +12 and fail at +8.
    See docs/prefetch-artifacts.md 3.1.
    """
    if len(raw) < 8:
        raise PrefetchError(Stage.CONTAINER, f"MAM container truncated at {len(raw)} bytes")
    flags = raw[3]
    out_size = struct.unpack_from("<I", raw, 4)[0]
    payload_offset = 12 if (flags & 0x80) else 8
    if len(raw) <= payload_offset:
        raise PrefetchError(Stage.CONTAINER, "MAM container has no payload")
    return payload_offset, out_size


def decompress(raw: bytes, prefer: str | None = None) -> bytes:
    """Decompress a MAM container. `prefer` forces 'ntdll' or 'pure' (the --decompressor flag).

    Falls back to the pure decoder if ntdll is unavailable, so a forced 'ntdll' on Linux is an
    explicit error rather than a silent downgrade.
    """
    payload_offset, out_size = parse_header(raw)
    if out_size > MAX_DECOMPRESSED_BYTES:
        raise PrefetchError(
            Stage.CONTAINER,
            f"container declares {out_size:,} bytes of output, above the "
            f"{MAX_DECOMPRESSED_BYTES:,} byte ceiling")
    payload = raw[payload_offset:]

    if prefer == "ntdll":
        if _NTDLL is None:
            raise PrefetchError(Stage.CONTAINER, "ntdll decompressor requested but unavailable")
        return _NTDLL(payload, out_size)
    if prefer == "pure":
        return xpress.decompress(payload, out_size, MAX_DECOMPRESSED_BYTES)

    if _NTDLL is not None:
        try:
            return _NTDLL(payload, out_size)
        except PrefetchError:
            # The OS refused this buffer; the pure decoder may still handle it. Whichever
            # answer we get, it is checked against out_size below by the caller.
            pass
    return xpress.decompress(payload, out_size, MAX_DECOMPRESSED_BYTES)


def load(raw: bytes, prefer: str | None = None) -> bytes:
    """Return the decompressed body, or the input unchanged if it is not a container."""
    if not is_container(raw):
        return raw
    try:
        return decompress(raw, prefer)
    except PrefetchError:
        raise
    except Exception as exc:                       # xpress raises its own exception type
        raise PrefetchError(Stage.CONTAINER, f"{type(exc).__name__}: {exc}") from exc
