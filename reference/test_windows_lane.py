#!/usr/bin/env python3
"""The Windows-only code paths, exercised on any host.

This tool targets Windows and has never run there. Three things genuinely cannot be checked
anywhere else: `FindFirstStreamW` against a real NTFS volume, the bytes `RtlDecompressBufferEx`
returns, and the frozen `.exe` under a Windows loader. **Everything above those three calls
can be**, and this suite does it:

  * the `ntdll` wrapper against a stub - status handling, buffer sizes, the error text;
  * `_Win32Backend` against a stub `kernel32` - including the ctypes declarations themselves,
    which no test could reach before because `__init__` could not be entered off Windows;
  * the `\\\\?\\` long-path transformation, in Windows path semantics, via `ntpath`;
  * creation time, where Windows means something different by `st_ctime` than Linux does;
  * console encoding, which is why a Cyrillic filename used to kill a run - reproducible here
    by forcing the stream encoding, exactly as `PYTHONIOENCODING=cp1252` does.

Vendored inputs only: no corpus, no Qt, no Windows. It runs on every machine, which is the
whole point - the lane that cannot be executed is the lane that must be checked hardest.

Run:  python3 test_windows_lane.py
"""

import ctypes
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from prefetch_core import ads, container, winpath  # noqa: E402
from prefetch_core.errors import PrefetchError  # noqa: E402
from prefetch_core.output import make_stdio_safe  # noqa: E402

failures = []


def check(label, got, want=True):
    ok = got == want
    print(f"  {label:60} {str(got):>12}{'' if ok else f'   << expected {want}'}")
    if not ok:
        failures.append(f"{label}: {got!r} != {want!r}")


class _Fn:
    """A stand-in for a ctypes foreign function: callable, and accepts the declarations."""

    def __init__(self, impl):
        self.impl = impl
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.impl(*args)


def _write_ulong(ptr, value):
    ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ulong)).contents.value = value


class _StubNtdll:
    """ntdll as the wrapper uses it. Statuses are what the real API would return."""

    def __init__(self, body=b"", workspace=4096, get_status=0, decompress_status=0,
                 short_by=0):
        self.body, self.workspace = body, workspace
        self.get_status, self.decompress_status = get_status, decompress_status
        self.short_by = short_by
        self.seen = {}
        self.RtlGetCompressionWorkSpaceSize = _Fn(self._get_size)
        self.RtlDecompressBufferEx = _Fn(self._decompress)

    def _get_size(self, fmt, ws_ptr, frag_ptr):
        self.seen["format"] = fmt.value if hasattr(fmt, "value") else fmt
        _write_ulong(ws_ptr, self.workspace)
        _write_ulong(frag_ptr, 32)
        return self.get_status

    def _decompress(self, fmt, out, out_size, payload, payload_size, written, workspace):
        self.seen["out_size"] = out_size.value if hasattr(out_size, "value") else out_size
        self.seen["payload_size"] = payload_size.value if hasattr(payload_size, "value") \
            else payload_size
        self.seen["payload"] = payload.value if hasattr(payload, "value") else payload
        self.seen["workspace_len"] = len(workspace)
        if self.decompress_status >= 0:
            out[0:len(self.body)] = self.body
            _write_ulong(written, len(self.body) - self.short_by)
        return self.decompress_status


class _StubKernel32:
    """kernel32's stream-enumeration trio, with the return values the API documents."""

    def __init__(self, streams, next_bool=1, first_handle=1234, last_error=38):
        self.streams = list(streams)
        self.next_bool, self.first_handle = next_bool, first_handle
        self.last_error = last_error
        self.closed = []
        self.index = 0
        self.FindFirstStreamW = _Fn(self._first)
        self.FindNextStreamW = _Fn(self._next)
        self.FindClose = _Fn(self._close)

    def _fill(self, buf):
        name, size = self.streams[self.index]
        data = ctypes.cast(buf, ctypes.POINTER(ads._Win32Backend._WIN32_FIND_STREAM_DATA))
        data.contents.StreamSize = size
        data.contents.cStreamName = name
        self.index += 1

    def _first(self, path, level, buf, flags):
        self.first_path = path.value if hasattr(path, "value") else path
        if not self.streams:
            return ctypes.c_void_p(-1).value
        self._fill(buf)
        return self.first_handle

    def _next(self, handle, buf):
        if self.index >= len(self.streams):
            return 0
        self._fill(buf)
        return self.next_bool

    def _close(self, handle):
        self.closed.append(handle)
        return 1


def main():
    print("1. the ntdll wrapper: statuses, buffers and the message an analyst reads\n")
    body = b"decompressed body, byte for byte"
    stub = _StubNtdll(body=body)
    decompress = container._probe_ntdll(load=lambda name: stub)
    check("the probe builds a decompressor from a usable ntdll", decompress is not None)
    got = decompress(b"compressed", len(body))
    check("it returns exactly what the OS wrote", got, body)
    check("...asking for XPRESS Huffman (format 4)", stub.seen["format"], 4)
    check("...with the output size the container declared", stub.seen["out_size"], len(body))
    check("...the payload it was given", stub.seen["payload"], b"compressed")
    check("...and a workspace of the size ntdll asked for", stub.seen["workspace_len"], 4096)

    # NTSTATUS is a signed 32-bit value, so every error status comes back negative. Formatting
    # it with %08X produced `0x-3FFFFFDD` - a code that matches nothing an analyst can look up,
    # in the message that is the only evidence the call failed (AUDIT BUG 98).
    failing = _StubNtdll(decompress_status=-1073741789)               # 0xC0000023
    decompress = container._probe_ntdll(load=lambda name: failing)
    try:
        decompress(b"x", 8)
        check("a failing decompression raises", False)
    except PrefetchError as exc:
        check("a failing decompression raises PrefetchError", True)
        check("...naming the call", "RtlDecompressBufferEx" in str(exc))
        check("...with the status as Windows spells it", "0xC0000023" in str(exc), True)
        check("...and not as a negative int", "0x-" not in str(exc), True)

    bad_workspace = _StubNtdll(get_status=-1073741823)                # 0xC0000001
    decompress = container._probe_ntdll(load=lambda name: bad_workspace)
    try:
        decompress(b"x", 8)
        check("a failing workspace query raises", False)
    except PrefetchError as exc:
        check("a failing workspace query names that call",
              "RtlGetCompressionWorkSpaceSize" in str(exc) and "0xC0000001" in str(exc))

    # NT_SUCCESS is `status >= 0`. Informational statuses are successes that carry a note -
    # STATUS_BUFFER_ALL_ZEROS (0x00000117) among them - and `status != 0` refused output the OS
    # had decoded correctly.
    informational = _StubNtdll(body=b"zeros", decompress_status=0x00000117)
    decompress = container._probe_ntdll(load=lambda name: informational)
    check("an informational NTSTATUS is a success, not a failure",
          decompress(b"x", 5), b"zeros")

    check("the declarations are made: workspace query returns a signed LONG",
          stub.RtlGetCompressionWorkSpaceSize.restype is ctypes.c_long)
    check("...and the decompressor too", stub.RtlDecompressBufferEx.restype is ctypes.c_long)
    check("...the output buffer as a pointer and the input as bytes",
          stub.RtlDecompressBufferEx.argtypes[1] is ctypes.c_void_p
          and stub.RtlDecompressBufferEx.argtypes[3] is ctypes.c_char_p
          and stub.RtlDecompressBufferEx.argtypes[6] is ctypes.c_void_p)
    check("...and the sizes as DWORDs",
          stub.RtlDecompressBufferEx.argtypes[2] is ctypes.c_ulong
          and stub.RtlDecompressBufferEx.argtypes[4] is ctypes.c_ulong)
    check("a host with no WinDLL simply has no ntdll decompressor",
          container._probe_ntdll(load=None) is None or sys.platform == "win32")

    print("\n2. FindFirstStreamW / FindNextStreamW, and the declarations themselves\n")
    SD = ads._Win32Backend._WIN32_FIND_STREAM_DATA
    # WIN32_FIND_STREAM_DATA is LARGE_INTEGER + WCHAR[MAX_PATH + 36]. A short buffer here is a
    # stack overwrite on a real host, not a test failure.
    wchar = ctypes.sizeof(ctypes.c_wchar)      # 2 on Windows, 4 where wchar_t is UCS-4
    check("the structure is LARGE_INTEGER + WCHAR[MAX_PATH + 36]",
          ctypes.sizeof(SD), 8 + 296 * wchar)
    check("...with the name at offset 8", SD.cStreamName.offset, 8)
    check("...296 wide characters long (MAX_PATH + 36)", SD.cStreamName.size // wchar, 296)
    check("...which is the documented 600 bytes where wchar_t is UTF-16",
          8 + 296 * 2, 600)

    k32 = _StubKernel32([("::$DATA", 0), (":hidden.pf:$DATA", 4096), (":notes:$DATA", 12)])
    backend = ads._Win32Backend(load=lambda name, use_last_error=False: k32)
    check("HANDLE is returned as a pointer, never a C int",
          k32.FindFirstStreamW.restype is ctypes.c_void_p)
    check("the path argument is wide, and the flags a DWORD",
          k32.FindFirstStreamW.argtypes == [ctypes.c_wchar_p, ctypes.c_int,
                                            ctypes.c_void_p, ctypes.c_ulong])
    # BOOL is a 4-byte int. `c_bool` reads one byte, so a BOOL whose low byte is zero reads as
    # the end of the enumeration - silently truncating the list of hidden streams.
    check("BOOL is declared as a 4-byte int, not a C99 bool",
          k32.FindNextStreamW.restype is ctypes.c_int)
    check("FindClose takes a HANDLE and returns BOOL",
          k32.FindClose.argtypes == [ctypes.c_void_p]
          and k32.FindClose.restype is ctypes.c_int)

    streams = backend.list_streams(r"C:\case\HOST.TXT")
    check("every stream is enumerated", len(streams), 3)
    check("the primary is recognised", [s.is_primary for s in streams], [True, False, False])
    check("names are decoded and stripped", [s.short_name for s in streams][1], "hidden.pf")
    check("sizes come through as 64-bit values", streams[1].size, 4096)
    check("the find handle is always closed", k32.closed, [1234])

    # Why that declaration matters, shown at the type level rather than asserted: reading a
    # 4-byte BOOL of 0x00000100 (TRUE) through a one-byte c_bool yields False - the end of the
    # enumeration, in the routine whose whole job is finding streams somebody hid. A stub
    # cannot reproduce this, because nothing crosses the ctypes boundary in a stub; the
    # declaration check above is the pin, and this is the mechanism it protects against.
    as_bool = ctypes.cast(ctypes.pointer(ctypes.c_int(0x100)),
                          ctypes.POINTER(ctypes.c_bool)).contents.value
    check("a 4-byte TRUE read as a 1-byte bool would read as FALSE", as_bool, False)
    wide_true = _StubKernel32([("::$DATA", 0), (":a:$DATA", 1), (":b:$DATA", 2)],
                              next_bool=0x100)
    backend2 = ads._Win32Backend(load=lambda name, use_last_error=False: wide_true)
    check("...and the enumeration treats any non-zero BOOL as TRUE",
          len(backend2.list_streams(r"C:\case\HOST.TXT")), 3)

    empty = _StubKernel32([])
    backend3 = ads._Win32Backend(load=lambda name, use_last_error=False: empty)
    import unittest.mock as _mock
    with _mock.patch.object(ads, "_get_last_error", lambda: 38):      # ERROR_HANDLE_EOF
        check("a file with no streams is an empty list, not an error",
              backend3.list_streams(r"C:\case\EMPTY.TXT"), [])
    with _mock.patch.object(ads, "_get_last_error", lambda: 5):       # ERROR_ACCESS_DENIED
        try:
            backend3.list_streams(r"C:\case\DENIED.TXT")
            check("a refused file raises rather than reporting 'no streams'", False)
        except OSError as exc:
            check("a refused file raises rather than reporting 'no streams'", True)
            check("...and the message carries the Win32 code",
                  "Win32 error 5" in str(exc), True)

    print("\n3. the long-path transformation, in Windows semantics\n")
    deep = "C:\\Cases\\" + "\\".join(f"segment{i:02d}" for i in range(30)) + "\\CALC.EXE-1.pf"
    check("an ordinary path is left exactly as it is",
          winpath._long_path_nt(r"C:\Windows\Prefetch\CALC.EXE-3FBEF7FD.pf"),
          r"C:\Windows\Prefetch\CALC.EXE-3FBEF7FD.pf")
    check(f"a {len(deep)}-character path is prefixed", winpath._long_path_nt(deep),
          "\\\\?\\" + deep)
    unc = "\\\\server\\share\\" + "x" * 240
    check("a UNC path gets the UNC form", winpath._long_path_nt(unc).startswith("\\\\?\\UNC\\"))
    check("...and keeps the server and share",
          winpath._long_path_nt(unc)[len("\\\\?\\UNC\\"):].startswith("server\\share\\"))
    check("a path already in the device namespace is untouched",
          winpath._long_path_nt("\\\\?\\C:\\" + "y" * 250), "\\\\?\\C:\\" + "y" * 250)
    check("an empty path is not turned into a prefix", winpath._long_path_nt(""), "")
    check("off Windows it is a no-op, whatever the length", winpath.long_path(deep),
          deep if sys.platform != "win32" else "\\\\?\\" + deep)

    print("\n4. creation time means different things on different platforms\n")

    class _Stat:
        st_ctime = 1_500_000_000.0
        st_mtime = 1_600_000_000.0

    with _mock.patch.object(sys, "platform", "win32"):
        stamped = winpath.creation_time(_Stat())
    check("on Windows without st_birthtime, st_ctime IS the creation time",
          stamped is not None and stamped.year == 2017, True)
    with _mock.patch.object(sys, "platform", "linux"):
        check("on Linux the same field is inode-change time and is refused",
              winpath.creation_time(_Stat()), None)

    class _StatBirth(_Stat):
        st_birthtime = 1_600_000_000.0

    with _mock.patch.object(sys, "platform", "win32"):
        birth = winpath.creation_time(_StatBirth())
    check("st_birthtime wins where the platform provides it", birth.year, 2020)

    print("\n5. a console that cannot spell the filename\n")
    # Windows picks stdout's encoding from the environment; redirect the output and it becomes
    # the ANSI code page. Printing a Cyrillic name to that stream raised UnicodeEncodeError and
    # ended the run with no report at all (AUDIT BUG 97).
    name = "КАЛЬК.EXE-3FBEF7FD.pf"
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", newline="")
    try:
        stream.write(name)
        stream.flush()
        check("a cp1252 stream refuses the name outright, as Windows does", False)
    except UnicodeEncodeError:
        check("a cp1252 stream refuses the name outright, as Windows does", True)

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", newline="")
    make_stdio_safe([stream])
    stream.write(name)
    stream.flush()
    check("after make_stdio_safe the write succeeds", raw.getvalue().decode("utf-8"), name)
    check("...and a redirected stream is UTF-8, not the code page", stream.encoding, "utf-8")

    class _Tty(io.TextIOWrapper):
        def isatty(self):
            return True

    console = _Tty(io.BytesIO(), encoding="cp1252", newline="")
    make_stdio_safe([console])
    check("a real console keeps its own encoding, so nothing is mojibaked",
          console.encoding, "cp1252")
    console.write(name)
    console.flush()
    check("...and the name is escaped rather than fatal",
          "\\u041a" in console.buffer.getvalue().decode("cp1252").lower()
          or "\\u041A" in console.buffer.getvalue().decode("cp1252"), True)

    class _NoReconfigure:
        encoding = "cp1252"

        def isatty(self):
            return False

    make_stdio_safe([_NoReconfigure()])      # must not raise
    check("a stream that cannot be reconfigured is left alone, not fatal", True)

    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
