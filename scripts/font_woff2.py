"""Keep valid, highly repetitive fonts within browser WOFF2 decoder limits."""
from io import BytesIO
import struct

import brotli
from fontTools.ttLib.woff2 import WOFF2Reader, WOFF2DirectoryEntry, woff2DirectorySize


def browser_compatible_woff2(data):
    reader = WOFF2Reader(BytesIO(data))
    transformed = reader.transformBuffer.getvalue()
    # Google's decoder rejects ratios over 100, including some valid Braille
    # fonts. Preserve the glyph transform and use gentler Brotli compression.
    # https://github.com/google/woff2/issues/184
    if len(transformed) <= 90 * len(data):
        return data
    assert not reader.metaOffset and not reader.privOffset
    stream = BytesIO(data)
    stream.seek(woff2DirectorySize)
    for _ in range(reader.numTables):
        WOFF2DirectoryEntry().fromFile(stream)
    offset = stream.tell()
    for quality in [9, 6, 4, 1, 0]:
        compressed = brotli.compress(transformed, mode=brotli.MODE_FONT, quality=quality)
        length = (offset + len(compressed) + 3) & ~3
        if len(transformed) > 90 * length:
            continue
        header = bytearray(data[:offset])
        struct.pack_into('>I', header, 8, length)
        struct.pack_into('>I', header, 20, len(compressed))
        result = bytes(header) + compressed + bytes(length - offset - len(compressed))
        assert WOFF2Reader(BytesIO(result)).transformBuffer.getvalue() == transformed
        return result
    raise ValueError('WOFF2 compression ratio exceeds browser decoder limit')
