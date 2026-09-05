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

import contextlib
import ctypes
import struct
from typing import Callable

from . import xpress
from .limits import MAX_DECOMPRESSED_BYTES
from .errors import PrefetchError, Stage

MAM_MAGIC = b"MAM"
COMPRESSION_FORMAT_XPRESS_HUFF = 4


def _nt_status(status: int) -> str:
    """Render an NTSTATUS the way Windows documents it.

    `f"0x{status:08X}"` on a *negative* Python int gives `0x-3FFFFFDD`, and every real NT error
    status has the high bit set - so on Windows, where this code is the only one that runs,
    every failure message was malformed. NTSTATUS is a signed 32-bit value; the name an analyst
    can look up is its unsigned form (AUDIT BUG 98).
    """
    return f"0x{status & 0xFFFFFFFF:08X}"


def _probe_ntdll(load=None) -> Callable[[bytes, int], bytes] | None:
    """Return an ntdll-backed decompressor, or None if it is unavailable for any reason.

    `load` exists so the wrapper can be exercised against a stub off Windows. Everything below
    the ctypes boundary is untestable here; everything above it - the status checks, the buffer
    sizes, the error text - is the part that was wrong, and is now reachable by a test.
    """
    load = load or getattr(ctypes, "WinDLL", None)
    if load is None:
        return None                              # not Windows: there is no WinDLL to call
    try:
        ntdll = load("ntdll")
        rtl = ntdll.RtlDecompressBufferEx
        get_size = ntdll.RtlGetCompressionWorkSpaceSize
    except (AttributeError, OSError):
        return None

    # Declared, not left to ctypes' defaults. NTSTATUS is a signed 32-bit LONG and the buffers
    # are pointers: on 64-bit Windows an undeclared pointer argument is marshalled as a C int
    # and truncated, which is the classic way this call "works" until it corrupts something.
    with contextlib.suppress(AttributeError, TypeError):
        get_size.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong),
                             ctypes.POINTER(ctypes.c_ulong)]
        get_size.restype = ctypes.c_long
        # The output buffer is an out-parameter (PUCHAR), so it is declared as a plain pointer;
        # `c_char_p` is for the input, which really is a pointer to bytes we own.
        rtl.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong,
                        ctypes.c_char_p, ctypes.c_ulong,
                        ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        rtl.restype = ctypes.c_long

    def decompress(payload: bytes, out_size: int) -> bytes:
        workspace_size = ctypes.c_ulong(0)
        fragment_size = ctypes.c_ulong(0)
        status = get_size(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
            ctypes.byref(workspace_size),
            ctypes.byref(fragment_size),
        )
        # NT_SUCCESS is `status >= 0`, not `status == 0`: severity lives in the top two bits, and
        # informational statuses (0x4xxxxxxx, and STATUS_BUFFER_ALL_ZEROS 0x00000117) are
        # successes that carry a note. Treating those as failures would refuse output the OS
        # decoded correctly - and the answer is checked against the declared size regardless.
        if status < 0:
            raise PrefetchError(Stage.CONTAINER,
                                f"RtlGetCompressionWorkSpaceSize: {_nt_status(status)}")
        out = ctypes.create_string_buffer(out_size)
        workspace = ctypes.create_string_buffer(workspace_size.value)
        written = ctypes.c_ulong(0)
        status = rtl(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
            out, ctypes.c_ulong(out_size),
            ctypes.c_char_p(payload), ctypes.c_ulong(len(payload)),
            ctypes.byref(written), workspace,
        )
        if status < 0:
            raise PrefetchError(Stage.CONTAINER,
                                f"RtlDecompressBufferEx: {_nt_status(status)}")
        # The OS reporting fewer bytes than the container declared is not an error status, but
        # it is a short read of the evidence, and returning it silently would hand the parser a
        # truncated body that looks whole. The caller compares against the declared size.
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


def decompress(raw: bytes, prefer: str | None = None, report: dict | None = None) -> bytes:
    """Decompress a MAM container. `prefer` forces 'ntdll' or 'pure' (the --decompressor flag).

    Falls back to the pure decoder if ntdll is unavailable, so a forced 'ntdll' on Linux is an
    explicit error rather than a silent downgrade.

    `report`, when given, is filled with `decompressor` and `trailing`: how many bytes of the
    container were left over after the compressed stream ended. A MAM container states the
    OUTPUT size and nothing about the input length, so bytes appended after the stream are
    carried along and decompress to nothing - a place to hide data inside a file that still
    parses perfectly (AUDIT BUG 78). Real files leave 0-3 bytes of bitstream padding.

    `trailing` is None when it could not be measured: `RtlDecompressBufferEx` does not report
    how much input it consumed, so on the ntdll path the answer is "not measured", never 0.
    Measuring it would mean decoding the stream a second time with the pure decoder, which is
    the entire cost of parsing the file - so it is offered, not imposed: `--decompressor pure`
    turns the check on.
    """
    payload_offset, out_size = parse_header(raw)
    if out_size > MAX_DECOMPRESSED_BYTES:
        raise PrefetchError(
            Stage.CONTAINER,
            f"container declares {out_size:,} bytes of output, above the "
            f"{MAX_DECOMPRESSED_BYTES:,} byte ceiling")
    payload = raw[payload_offset:]

    def _pure() -> bytes:
        # The decoder raises its own exception type for a malformed stream. `load()` converts
        # it, but `decompress()` is public too, and a caller reaching for it got an exception
        # from an internal module that no documented contract mentions - so a crafted container
        # escaped the one error type this package promises (AUDIT BUG 104). Converted here, at
        # the boundary, rather than only at the layer above it.
        try:
            body, consumed = xpress.decompress(payload, out_size, MAX_DECOMPRESSED_BYTES,
                                               with_consumed=True)
        except PrefetchError:
            raise
        except Exception as exc:                   # xpress.InvalidCompressedData and kin
            raise PrefetchError(Stage.CONTAINER,
                                f"{type(exc).__name__}: {exc}") from exc
        if report is not None:
            report["decompressor"] = "pure"
            report["trailing"] = len(payload) - consumed
        return body

    def _os_decoder() -> bytes:
        body = _NTDLL(payload, out_size)
        if report is not None:
            report["decompressor"] = "ntdll"
            report["trailing"] = None      # not measurable; see the docstring
        return body

    if prefer == "ntdll":
        if _NTDLL is None:
            raise PrefetchError(Stage.CONTAINER, "ntdll decompressor requested but unavailable")
        return _os_decoder()
    if prefer == "pure":
        return _pure()

    if _NTDLL is not None:
        try:
            return _os_decoder()
        except PrefetchError:
            # The OS refused this buffer; the pure decoder may still handle it. Whichever
            # answer we get, it is checked against out_size below by the caller.
            pass
    return _pure()


def load(raw: bytes, prefer: str | None = None, report: dict | None = None) -> bytes:
    """Return the decompressed body, or the input unchanged if it is not a container."""
    if not is_container(raw):
        if report is not None:
            report["decompressor"] = "none"
            report["trailing"] = 0        # an uncompressed file has no stream to end early
        return raw
    try:
        return decompress(raw, prefer, report)
    except PrefetchError:
        raise
    except Exception as exc:                       # xpress raises its own exception type
        raise PrefetchError(Stage.CONTAINER, f"{type(exc).__name__}: {exc}") from exc
