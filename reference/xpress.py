"""Re-export of the real XPRESS Huffman decoder, for `validate_spec.py`.

This used to be a second copy of the decoder. Two copies drift: an optimisation applied to one
and not the other means the spec-validation suite stops testing the code that actually ships,
while still reporting a clean pass.

The independence that matters for `validate_spec.py` is that its **parser** was written from
`docs/prefetch-format.md` rather than translated from the C#. The decompressor is a shared
primitive with a hard external correctness criterion - it either reproduces the declared
output size and a valid SCCA structure, or it does not - so sharing one implementation is
correct, and sharing it means `validate_spec.py` exercises the shipping decoder.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prefetch_core.xpress import (  # noqa: E402
    InvalidCompressedData,
    decompress,
    decompress_mam,
)

__all__ = ["InvalidCompressedData", "decompress", "decompress_mam"]
