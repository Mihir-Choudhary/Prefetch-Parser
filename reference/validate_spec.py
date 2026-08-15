#!/usr/bin/env python3
"""Validate docs/prefetch-format.md against the corpus.

Written ONLY from docs/prefetch-format.md - deliberately not a translation of the C#.
If this passes, the offset tables in the spec are correct for v17/v23/v26.
v30/31 cannot be checked here: they need an XPRESS Huffman decompressor.

Usage: python3 validate_spec.py
"""

import datetime
import glob
import os
import struct
import sys

import xpress

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus  # noqa: E402
CORPUS = os.path.join(HERE, "pf-corpus")

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def filetime(raw):
    return FILETIME_EPOCH + datetime.timedelta(microseconds=raw // 10)


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def i64(b, o):
    return struct.unpack_from("<q", b, o)[0]


def utf16(b, o, nbytes):
    return b[o:o + nbytes].decode("utf-16-le")


def mft_ref(b, o):
    """spec section 7: 6-byte entry number, 2-byte sequence number"""
    entry = int.from_bytes(b[o:o + 6], "little")
    seq = u16(b, o + 6)
    return entry, (seq if seq else None)


class Prefetch:
    pass


def parse(data):
    pf = Prefetch()

    # --- spec section 1: dispatch -------------------------------------------
    if data[0:3] == b"MAM":
        data = xpress.decompress_mam(data)
    pf.raw = data
    pf.version = i32(data, 0)
    if data[4:8] != b"SCCA":
        raise ValueError("Invalid signature! Should be 'SCCA'")

    # --- spec section 2: header, 84 bytes at 0 ------------------------------
    pf.file_size = i32(data, 0x0C)
    name = utf16(data, 0x10, 60)
    if "\0" not in name:
        raise ValueError("executable name is not NUL terminated")
    pf.exe_name = name.split("\0")[0].strip()
    pf.hash = "%08X" % u32(data, 0x4C)          # spec: X8, not X

    # --- spec section 3: file information section at 84 ---------------------
    fi = 84
    pf.metrics_offset = i32(data, fi + 0)
    pf.metrics_count = i32(data, fi + 4)
    pf.chains_offset = i32(data, fi + 8)
    pf.chains_count = i32(data, fi + 12)
    pf.names_offset = i32(data, fi + 16)
    pf.names_size = i32(data, fi + 20)
    pf.vols_offset = i32(data, fi + 24)
    pf.vol_count = i32(data, fi + 28)
    pf.vols_size = i32(data, fi + 32)

    if pf.version == 17:                                    # spec 3.2
        pf.total_dir_count = -1
        pf.run_times = [filetime(i64(data, fi + 36))]
        pf.run_count = i32(data, fi + 60)
        metric_size, chain_size, vol_size = 20, 12, 40
        fileinfo_size = 68
    elif pf.version == 23:                                  # spec 3.3
        pf.total_dir_count = i32(data, fi + 36)
        pf.run_times = [filetime(i64(data, fi + 44))]
        pf.run_count = i32(data, fi + 68)
        metric_size, chain_size, vol_size = 32, 12, 104
        fileinfo_size = 156
    elif pf.version == 26:                                  # spec 3.4
        pf.total_dir_count = i32(data, fi + 36)
        pf.run_times = [filetime(i64(data, fi + 44 + 8 * i)) for i in range(8)
                        if i64(data, fi + 44 + 8 * i) > 0]
        pf.run_count = i32(data, fi + 124)
        metric_size, chain_size, vol_size = 32, 12, 104
        fileinfo_size = 220        # measured, not the C#'s 224 - see spec 3.4
    elif pf.version in (30, 31):                            # spec 3.5
        pf.total_dir_count = i32(data, fi + 36)
        pf.run_times = [filetime(i64(data, fi + 44 + 8 * i)) for i in range(8)
                        if i64(data, fi + 44 + 8 * i) > 0]
        metric_size, chain_size, vol_size = 32, 8, 96
        # The file-info section is 220 on 2015-era v30 and 212 on modern v30/v31.
        # It is self-describing: FileMetricsOffset is the first byte after it.
        # RunCount always sits 96 bytes before the section end - deriving it that way
        # replaces PECmd's "probe +120, else shift back 8" heuristic. See spec 3.0a.
        fileinfo_size = pf.metrics_offset - 84
        pf.run_count = i32(data, fi + fileinfo_size - 96)
    else:
        raise ValueError("Unknown version '%X'" % pf.version)
    pf.fileinfo_size = fileinfo_size
    pf.metric_size = metric_size

    # --- spec section 4: file metrics ---------------------------------------
    pf.metrics = []
    for i in range(pf.metrics_count):
        o = pf.metrics_offset + i * metric_size
        if pf.version == 17:
            pf.metrics.append({"name_offset": i32(data, o + 8),
                               "name_size": i32(data, o + 12),
                               "mft": None})
        else:
            pf.metrics.append({"name_offset": i32(data, o + 12),
                               "name_size": i32(data, o + 16),
                               "mft": mft_ref(data, o + 24)})

    # --- spec section 4 (trace chains) --------------------------------------
    pf.chain_size = chain_size
    pf.chains_end = pf.chains_offset + chain_size * pf.chains_count

    # --- spec section 5: filename strings -----------------------------------
    blob = data[pf.names_offset:pf.names_offset + pf.names_size]
    pf.filenames = [s for s in blob.decode("utf-16-le").split("\0") if s]

    # names resolved via the per-metric offsets instead (spec 4).
    # name_offset is a BYTE offset from names_offset; name_size is a CHARACTER
    # count excluding the NUL - established empirically, see spec 4.
    pf.filenames_via_metrics = [
        utf16(data, pf.names_offset + m["name_offset"], m["name_size"] * 2)
        for m in pf.metrics
    ]

    # --- spec section 5a: trailing executable-path / package-identity string --
    # Modern v30/v31 store a NUL-terminated UTF-16 string between the filename block
    # and the volume block: the executable's own full device path, or - for packaged
    # (Store/UWP) apps - the package identity. Older versions leave only alignment
    # padding here.
    names_end = pf.names_offset + pf.names_size
    raw_tail = data[names_end:pf.vols_offset]
    tail = raw_tail.decode("utf-16-le", errors="replace").split("\0")[0]
    pf.exec_path_field = tail if len(tail) > 8 else None
    pf.tail_bytes = len(raw_tail)

    # --- spec section 6: volume information ---------------------------------
    pf.volumes = []
    for j in range(pf.vol_count):
        vo = pf.vols_offset + j * vol_size
        dev_offset = i32(data, vo + 0)
        dev_chars = i32(data, vo + 4)
        created = filetime(i64(data, vo + 8))
        serial = "%08X" % u32(data, vo + 16)
        refs_offset = i32(data, vo + 20)
        refs_size = i32(data, vo + 24)
        dirs_offset = i32(data, vo + 28)
        dirs_count = i32(data, vo + 32)

        dev_name = utf16(data, pf.vols_offset + dev_offset, dev_chars * 2)

        # 6.1 file references
        ro = pf.vols_offset + refs_offset
        num_refs = i32(data, ro + 4)
        refs = []
        p = ro + 8
        while p + 8 <= ro + refs_size and len(refs) < num_refs:
            refs.append(mft_ref(data, p))
            p += 8

        # 6.2 directory strings
        do = pf.vols_offset + dirs_offset
        dirs = []
        p = do
        for _ in range(dirs_count):
            nchars = u16(data, p)
            p += 2
            dirs.append(utf16(data, p, nchars * 2 + 2).rstrip("\0"))
            p += nchars * 2 + 2
        pf.dirs_walk_end = p

        pf.volumes.append({"device": dev_name, "serial": serial, "created": created,
                           "dirs": dirs, "refs": refs})
    return pf


# ---------------------------------------------------------------------------
# Ground truth transcribed from reference/TestVersion17.cs / 23.cs / 26.cs.
# Test times are -07:00; converted to UTC here.
# ---------------------------------------------------------------------------
def utc(s):
    return datetime.datetime.fromisoformat(s).astimezone(datetime.timezone.utc)


GROUND_TRUTH = [
    ("Win2k3/CMD.EXE-087B4001.pf", {
        "exe_name": "CMD.EXE", "hash": "087B4001", "file_size": 6002,
        "run_time0": utc("2016-01-15T16:01:40.8750000-07:00"), "run_count": 3,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME1", "serial": "64BB3469",
        "vol_created": utc("2016-01-15T08:45:15.8906250-07:00"),
        "dir_count": 4, "dir3": "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\",
        "ref_count": 20, "name_count": 16,
        "name3": r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\LOCALE.NLS",
    }),
    ("XPPro/CALC.EXE-02CD573A.pf", {
        "exe_name": "CALC.EXE", "hash": "02CD573A", "file_size": 11332,
        "run_time0": utc("2016-01-13T15:05:51.2812500-07:00"), "run_count": 3,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME1", "serial": "E0F7E847",
        "vol_created": utc("2016-01-13T04:17:18.7187500-07:00"),
        "dir_count": 6, "dir3": "\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\",
    }),
    ("Vista/EXPLORER.EXE-7A3328DA.pf", {
        "exe_name": "EXPLORER.EXE", "hash": "7A3328DA", "file_size": 38470,
        "run_time0": utc("2016-01-16T13:02:00.8326765-07:00"), "run_count": 1,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME1", "serial": "E8EAB8B5",
        "vol_created": utc("2016-01-16T13:53:13.1093750-07:00"),
        "dir_count": 13, "dir3": r"\DEVICE\HARDDISKVOLUME1\USERS\PUBLIC",
        "ref_count": 84, "name_count": 66,
        "name3": r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\ADVAPI32.DLL",
        "ref1": (352, None),
    }),
    ("Win7/DCODEDCODEDCODEDCODEDCODEDCOD-9054DA3F.pf", {
        "exe_name": "DCODEDCODEDCODEDCODEDCODEDCOD", "hash": "9054DA3F",
        "file_size": 29746,
        "run_time0": utc("2016-01-22T09:23:16.3416250-07:00"), "run_count": 5,
        "vol_count": 2, "device": r"\DEVICE\HARDDISKVOLUME2", "serial": "88008C2F",
        "vol_created": utc("2016-01-16T14:15:18.1093750-07:00"),
        "dir_count": 14,
    }),
    ("Win2012R2/NOTEPAD.EXE-D8414F97.pf", {
        "exe_name": "NOTEPAD.EXE", "hash": "D8414F97", "file_size": 15320,
        "run_time0": utc("2016-01-16T14:40:31.2944718-07:00"), "run_count": 2,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME2", "serial": "7450B65F",
        "vol_created": utc("2016-01-16T15:21:57.7889266-07:00"),
        "dir_count": 7,
        "dir3": r"\DEVICE\HARDDISKVOLUME2\WINDOWS\GLOBALIZATION\SORTING",
        "ref_count": 35, "name_count": 26,
        "name3": r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\ADVAPI32.DLL",
        "ref5": (0, None), "ref1": (18972, None),
    }),
    ("Win2012/REGEDIT.EXE-90FEEA06.pf", {
        "exe_name": "REGEDIT.EXE", "hash": "90FEEA06", "file_size": 22982,
        "run_time0": utc("2016-01-16T14:36:18.7186980-07:00"), "run_count": 1,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME2", "serial": "2E25F20A",
        "vol_created": utc("2016-01-16T15:20:46.1666157-07:00"),
        "dir_count": 12,
        "dir3": r"\DEVICE\HARDDISKVOLUME2\USERS\ADMINISTRATOR\APPDATA\LOCAL",
        "ref_count": 62, "name_count": 42,
        "ref5": (27324, None), "ref9": (29316, None),
    }),
    ("Win8x/CALC.EXE-77FDF17F.pf", {
        "exe_name": "CALC.EXE", "hash": "77FDF17F", "file_size": 22048,
        "run_time0": utc("2016-01-16T14:10:26.0583417-07:00"), "run_count": 2,
        "vol_count": 1, "device": r"\DEVICE\HARDDISKVOLUME2", "serial": "C6EE7444",
        "vol_created": utc("2016-01-16T15:04:54.3519546-07:00"),
        "dir_count": 7,
        "dir3": r"\DEVICE\HARDDISKVOLUME2\WINDOWS\GLOBALIZATION\SORTING",
    }),
]

fails = []


def check(label, got, want):
    if got != want:
        fails.append("%s: got %r, want %r" % (label, got, want))


def main():
    # --- ground-truth checks -------------------------------------------------
    for rel, gt in GROUND_TRUTH:
        path = os.path.join(CORPUS, rel)
        pf = parse(open(path, "rb").read())
        p = lambda k: "%s %s" % (rel, k)

        check(p("exe_name"), pf.exe_name, gt["exe_name"])
        # spec says X8; tests assert the reference's X (leading zero trimmed)
        check(p("hash"), pf.hash.lstrip("0") or "0", gt["hash"].lstrip("0") or "0")
        check(p("hash_is_8_chars"), len(pf.hash), 8)
        check(p("file_size"), pf.file_size, gt["file_size"])
        check(p("run_time0"), pf.run_times[0], gt["run_time0"])
        check(p("run_count"), pf.run_count, gt["run_count"])
        check(p("vol_count"), len(pf.volumes), gt["vol_count"])
        v0 = pf.volumes[0]
        check(p("device"), v0["device"], gt["device"])
        check(p("serial"), v0["serial"].lstrip("0"), gt["serial"].lstrip("0"))
        check(p("vol_created"), v0["created"], gt["vol_created"])
        check(p("dir_count"), len(v0["dirs"]), gt["dir_count"])
        if "dir3" in gt:
            check(p("dir3"), v0["dirs"][3], gt["dir3"])
        if "ref_count" in gt:
            check(p("ref_count"), len(v0["refs"]), gt["ref_count"])
        if "name_count" in gt:
            check(p("name_count"), len(pf.filenames), gt["name_count"])
        if "name3" in gt:
            check(p("name3"), pf.filenames[3], gt["name3"])
        for k in ("ref1", "ref5", "ref9"):
            if k in gt:
                check(p(k), v0["refs"][int(k[3:])], gt[k])

    print("ground truth: %d files checked" % len(GROUND_TRUTH))

    # --- corpus-wide invariants ---------------------------------------------
    corpora = [("vendored", os.path.join(CORPUS, "*", "*.pf"))]
    for extra in (os.path.join(corpus.WIN10, "*.pf"),
                  os.path.join(corpus.WIN11, "*.pf")):
        if glob.glob(extra):
            corpora.append((extra.split("/")[4], extra))

    for label, pattern in corpora:
        checked = 0
        byver = {}
        for path in sorted(glob.glob(pattern)):
            rel = os.path.basename(path)
            data = open(path, "rb").read()
            if rel.startswith("notAPrefetch"):
                try:
                    parse(data)
                    fails.append(f"{rel}: expected invalid-signature error")
                except ValueError:
                    pass
                continue
            pf = parse(data)
            checked += 1
            byver[pf.version] = byver.get(pf.version, 0) + 1
            tag = f"{label}/{rel}"

            check(f"{tag} filenames==FileMetricsCount",
                  len(pf.filenames), pf.metrics_count)
            check(f"{tag} VolumeCount==len(volumes)", pf.vol_count, len(pf.volumes))

            # section geometry (spec section 3)
            check(f"{tag} metrics_offset==84+fileinfo_size",
                  pf.metrics_offset, 84 + pf.fileinfo_size)
            check(f"{tag} chains_offset==metrics end", pf.chains_offset,
                  pf.metrics_offset + pf.metrics_count * pf.metric_size)
            check(f"{tag} names_offset==chains end", pf.names_offset, pf.chains_end)
            # vols_offset = align8(names_end + trailing string, if any)  [spec 5a]
            names_end = pf.names_offset + pf.names_size
            if pf.exec_path_field is None:
                check(f"{tag} vols_offset==align8(names end)", pf.vols_offset,
                      (names_end + 7) // 8 * 8)
            else:
                strbytes = (len(pf.exec_path_field) + 1) * 2
                lo = names_end + strbytes
                slack = pf.vols_offset - lo
                if not (0 <= slack < 16) or pf.vols_offset % 8:
                    fails.append(f"{tag}: vols_offset {pf.vols_offset} not 8-aligned "
                                 f"within 16B of names_end+string {lo} (slack {slack})")

            # per-metric filename offsets reproduce the NUL-split list (spec section 4)
            if pf.filenames_via_metrics != pf.filenames:
                fails.append(f"{tag}: per-metric name offsets disagree with NUL-split names")

            if pf.dirs_walk_end > len(pf.raw):
                fails.append(f"{tag}: directory string walk ran past EOF")

            # TotalDirectoryCount (spec 3.3/3.4) - v17 stores -1
            if pf.version != 17:
                check(f"{tag} TotalDirectoryCount==sum(dirs)", pf.total_dir_count,
                      sum(len(v["dirs"]) for v in pf.volumes))

            # RunCount must be consistent with the retained run times
            if pf.run_count < len(pf.run_times):
                fails.append(f"{tag}: RunCount {pf.run_count} < retained run times "
                             f"{len(pf.run_times)}")
            if not 0 <= pf.run_count < 1000000:
                fails.append(f"{tag}: implausible RunCount {pf.run_count}")

        vers = ", ".join(f"v{v}x{n}" for v, n in sorted(byver.items()))
        print(f"{label:16s} {checked:4d} files checked   ({vers})")

    if fails:
        print("\nFAILURES (%d):" % len(fails))
        for f in fails:
            print("  " + f)
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
