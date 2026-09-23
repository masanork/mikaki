"""Extract installed FIDO tool metadata into ignored, disposable test storage."""
import json
import os
from pathlib import Path
import struct

source = Path(os.environ.get('FIDO_ASAR', '/Applications/FIDO Alliance - Certification Conformance Testing Tools.app/Contents/Resources/app.asar'))
target = Path(__file__).resolve().parents[2] / 'target' / 'fido-metadata'
target.mkdir(parents=True, exist_ok=True)
with source.open('rb') as stream:
    if struct.unpack('<I', stream.read(4))[0] != 4:
        raise ValueError('Unexpected ASAR header')
    stream.read(8)
    size = struct.unpack('<I', stream.read(4))[0]
    if size > 16_777_216:
        raise ValueError('ASAR header too large')
    tree = json.loads(stream.read(size))
    stream.read((-size) % 4)
    base = stream.tell()
    for name in ('modules', 'fido2-server-conformance-module', 'metadata'):
        tree = tree['files'][name]
    count = 0
    for name, entry in tree['files'].items():
        if not name.endswith('.json') or Path(name).name != name or 'files' in entry:
            continue
        if entry['size'] > 1_048_576:
            raise ValueError('Metadata statement too large')
        stream.seek(base + int(entry['offset']))
        (target / name).write_bytes(stream.read(entry['size']))
        count += 1
if not count:
    raise ValueError('No FIDO metadata found')
print(f'Extracted {count} test metadata statements to {target}')
