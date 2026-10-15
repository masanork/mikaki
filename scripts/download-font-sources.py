"""Fetch pinned upstream font archives and their original license texts."""
import hashlib
from pathlib import Path
import urllib.request
from zipfile import ZipFile

root = Path(__file__).resolve().parents[1]
sources = root / 'local/generated/font-sources'
licenses = sources
sources.mkdir(parents=True, exist_ok=True)
licenses.mkdir(parents=True, exist_ok=True)
archives = [
    # Used to measure the intentional coverage gap; never shipped to clients.
    ('acgj.zip', 'https://www.digital.go.jp/assets/contents/node/basic_page/field_ref_resources/f3a1de20-1f15-44fd-ade8-4e0e9eb52e8b/b5f08c73/20260818_policies_local_govarnments_outline_01.zip',
     'b016e08a994158adfe5a89cd7a3e893986fb10e24b1239a0e971ceaf74583ee2',
     {'acgjm.ttf': sources / 'acgj-acgjm.ttf'}),
    ('inter.zip', 'https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip',
     '9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e',
     {'web/InterVariable.woff2': sources / 'InterVariable.woff2',
      'web/InterVariable-Italic.woff2': sources / 'InterVariable-Italic.woff2',
      'LICENSE.txt': licenses / 'Inter-OFL.txt'}),
]
for filename, url, expected, files in archives:
    archive = sources / filename
    if not archive.exists():
        urllib.request.urlretrieve(url, archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == expected, f'Archive changed: {url}'
    with ZipFile(archive) as zip:
        for suffix, target in files.items():
            matches = [name for name in zip.namelist() if name == suffix or name.endswith('/' + suffix)]
            assert len(matches) == 1, f'Ambiguous archive entry: {suffix}'
            target.write_bytes(zip.read(matches[0]))
    print(f'Verified {filename}')
