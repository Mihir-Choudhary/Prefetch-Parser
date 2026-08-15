"""Resource ceilings, in one place.

Every input this tool reads is attacker-influenced: a Prefetch folder can be written to, a
carrier file's stream is chosen by whoever created it, and a `MAM` container declares its own
uncompressed size. "Scan this folder" must not become an out-of-memory crash because someone
planted a 4 GB `Layout.ini` or a container claiming to expand to 16 GB.

These are deliberately generous - orders of magnitude above anything observed - so they never
fire on real evidence. They exist to bound the pathological case, not to police the normal one.

Observed maxima across both corpora, for scale:

    Layout.ini            584 KB
    ReadyBoot Trace*.fx   3.2 MB
    dynrespri.7db         393 KB
    PfPre_*.mkd           197 KB (fixed size)
    largest .pf           under 200 KB

Exceeding a ceiling is always reported as a problem on the record, never a silent skip: an
analyst must be able to tell "this file was not fully examined" from "this file was clean".
"""

# One artifact file read whole into memory.
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

# Decompressed output from a single MAM container. XPRESS Huffman needs a 256-byte Huffman
# table per 64 KB block, so a crafted container can legitimately expand roughly 256x - which
# turns a 64 MB input into 16 GB of output without anything being malformed.
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024

# One NTFS alternate data stream.
MAX_STREAM_BYTES = 64 * 1024 * 1024
