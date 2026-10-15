"""Generate and verify static WOFF2 chunks using gjs's IVS-aware WASM subsetter.

Requires fonttools[woff] for cmap repair and glyph verification (not subsetting).
Normal builds consume committed assets; only regeneration needs the gjs checkout.
"""
import argparse
import hashlib
import json
import logging
import multiprocessing
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from font_woff2 import browser_compatible_woff2
from fontTools.ttLib import TTFont
from fontTools.merge import Merger
from fontTools.pens.recordingPen import DecomposingRecordingPen

# The generated Bunsen sources have pre-OpenType epoch timestamps. Avoid
# repeating this harmless source-metadata warning for every validated chunk.
logging.getLogger('fontTools.ttLib.tables._h_e_a_d').setLevel(logging.ERROR)

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--gjs', type=Path, default=Path.home() / 'repo/gjs')
parser.add_argument('--sources', type=Path, default=ROOT / 'local/generated/font-sources')
parser.add_argument('--wasm-dir', type=Path, default=ROOT / 'local/generated/gjs-subsetter')
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--work', type=Path, required=True)
args = parser.parse_args()
work = args.work
work.mkdir(parents=True, exist_ok=True)
output = args.output
output.mkdir(parents=True, exist_ok=True)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def ranges(cps):
    result = []
    for cp in sorted(cps):
        if result and cp == result[-1][1] + 1:
            result[-1][1] = cp
        else:
            result.append([cp, cp])
    return ','.join(f'U+{a:X}' if a == b else f'U+{a:X}-{b:X}' for a, b in result)

def cjk(cp):
    return (0x3400 <= cp <= 0x9fff or 0xf900 <= cp <= 0xfaff
            or 0x20000 <= cp <= 0x323af)

def variants(font):
    return {(base, vs): glyph or font.getBestCmap()[base]
            for table in font['cmap'].tables if table.format == 14
            for vs, rows in table.uvsDict.items() for base, glyph in rows}

def outline(font, glyph):
    if not hasattr(font, '_mikaki_glyphset'):
        font._mikaki_glyphset = font.getGlyphSet()
        font._mikaki_outlines = {}
    if glyph in font._mikaki_outlines:
        return font._mikaki_outlines[glyph]
    pen = DecomposingRecordingPen(font._mikaki_glyphset)
    font._mikaki_glyphset[glyph].draw(pen)
    result = digest(repr(pen.value).encode())
    font._mikaki_outlines[glyph] = result
    return result

def run(jobs):
    groups = {}
    for job in jobs:
        groups.setdefault(job['source'], []).append(job)
    def subset_group(item):
        index, source_jobs = item
        path = work / f'jobs-{index}.json'
        path.write_text(json.dumps(source_jobs, ensure_ascii=False))
        subprocess.run(['node', str(ROOT / 'scripts/gjs-fonts.mjs'),
                        str(args.wasm_dir), str(path)], check=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(subset_group, enumerate(groups.values())))

sources = []
for style in ['Mincho', 'Gothic']:
    for layer in ['', 'Ext', 'PUP']:
        family = f'Bunsen{style}{layer}'
        key = f'bunsen-{style.lower()}' + (f'-{layer.lower()}' if layer else '')
        sources.append((key, family,
                        args.gjs / 'data/output/bunsen-build' / f'{family}-Regular.ttf',
                        400, 'CC0-1.0'))
common = set()
for path in [ROOT / 'messages/ja.json', *sorted((ROOT / 'website/content').rglob('*.md'))]:
    common.update(ord(ch) for ch in path.read_text() if cjk(ord(ch)))

jobs, records, families = [], {}, []
coverage = {'Mincho': set(), 'Gothic': set()}
variation_coverage = {'Mincho': set(), 'Gothic': set()}
for key, family, path, weight, license in sources:
    font = TTFont(path, recalcTimestamp=False)
    cmap = font.getBestCmap()
    source_cps = set(cmap)
    ivs = variants(font)
    style = 'Mincho' if 'Mincho' in family else 'Gothic'
    coverage[style].update(source_cps)
    variation_coverage[style].update(ivs)
    # Some Ext variants have no ordinary base mapping in that source. A valid
    # standalone browser font still needs one: alias its first source variant.
    # The Base family owns the unadorned character and precedes Ext in the stack.
    # No new private-use coverage is inferred from these variation-base aliases.
    variation_aliases = {}
    for (base, vs), glyph in sorted(ivs.items()):
        if base not in source_cps:
            variation_aliases.setdefault(base, glyph)
    assert set(variation_aliases) <= coverage[style], 'Variation alias lacks a preceding base glyph'
    for table in font['cmap'].tables:
        if table.format == 12:
            table.cmap.update(variation_aliases)
    cmap = font.getBestCmap()
    cps = set(cmap)
    # gjs reads non-default UVS mappings. Express default UVS as explicit
    # references to the same base glyph so those sequences survive subsetting.
    for table in font['cmap'].tables:
        if table.format == 14:
            table.uvsDict = {vs: [(b, glyph or cmap[b]) for b, glyph in rows]
                             for vs, rows in table.uvsDict.items()}
    prepared = work / f'{key}.ttf'
    font.save(prepared)
    buckets = {}
    # Ext also holds variation sequences whose plain base is in the Base font.
    # Keep these even when Ext has no ordinary cmap entry for that codepoint.
    for cp in sorted(cps | {base for base, _ in ivs}):
        bucket = 'common' if cp in common else f'{cp >> 8:04x}'
        buckets.setdefault(bucket, []).append(cp)
    for bucket, points in buckets.items():
        sequences = {pair: glyph for pair, glyph in ivs.items() if pair[0] in points}
        base_points = set(points) & cps
        text = ''.join(map(chr, sorted(base_points)))
        text += ''.join(chr(b) + chr(v) for b, v in sorted(sequences))
        raw = work / f'{key}-{bucket}.otf'
        jobs.append({'source': str(prepared), 'text': text, 'output': str(raw)})
        records.setdefault((style, bucket), []).append((font, cmap, set(points) & source_cps, sequences, raw))
    families.append({'id': key, 'family': family, 'weight': weight, 'license': license,
                     'source': str(path.relative_to(args.gjs) if path.is_relative_to(args.gjs)
                                   else path.name), 'sha256': digest(path.read_bytes()),
                     'codepoints': len(source_cps), 'variation_sequences': len(ivs),
                     'variation_base_aliases': len(variation_aliases)})
    print(f'{key}: {len(source_cps)} source codepoints, {len(ivs)} variation sequences', flush=True)
run(jobs)

latin_cps = set(TTFont(args.sources / 'InterVariable.woff2').getBestCmap())
record_items = list(records.items())
def build_chunk(index):
    (style, bucket), layers = record_items[index]
    family = f'Bunsen{style}'
    # A variation sequence must live in the same physical font as its base.
    # WebKit does not reliably search another family for a missing UVS mapping.
    # Merge only matching chunks, staying well below OpenType's glyph limit.
    allowed = {str(raw): points for _, _, points, _, raw in layers}
    class ChunkMerger(Merger):
        def _openFonts(self, paths):
            fonts = super()._openFonts(paths)
            for font, path in zip(fonts, paths):
                for table in font['cmap'].tables:
                    if table.format in (4, 12):
                        table.cmap = {cp: glyph for cp, glyph in table.cmap.items()
                                      if cp in allowed[str(path)]}
            return fonts
    merged = ChunkMerger().merge([str(raw) for _, _, _, _, raw in layers])
    merged.recalcTimestamp = False
    # fontTools' merger stamps both dates independently of recalcTimestamp.
    timestamp = json.loads((ROOT / 'scripts/fonts.lock.json').read_text())['source_date_epoch'] + 2082844800
    merged['head'].created = merged['head'].modified = timestamp
    assert len(merged.getGlyphOrder()) < 65536, 'Chunk exceeds OpenType glyph limit'
    # WebKit can use a loaded font's physical cmap outside its CSS range.
    # Give overlapping Latin characters exclusively to Inter in the cmap too.
    for table in merged['cmap'].tables:
        if table.format in (4, 12):
            table.cmap = {cp: glyph for cp, glyph in table.cmap.items() if cp not in latin_cps}
    cmap = merged.getBestCmap() or {}
    if not cmap:
        return None, None
    ivs = variants(merged)
    assert not {base for base, _ in ivs} & latin_cps, 'Inter overlaps a Japanese UVS base'
    expected, expected_ivs = {}, {}
    for original, original_cmap, points, sequences, _ in layers:
        for cp in sorted(points - latin_cps):
            expected.setdefault(cp, (original, original_cmap[cp]))
        for pair, glyph in sorted(sequences.items()):
            expected_ivs.setdefault(pair, (original, glyph))
    assert set(cmap) == set(expected), f'cmap mismatch: {style}/{bucket}'
    assert set(ivs) == set(expected_ivs), f'IVS mismatch: {style}/{bucket}'
    for cp, (original, glyph) in expected.items():
        assert outline(original, glyph) == outline(merged, cmap[cp]), f'Glyph mismatch {cp:X}'
        assert original['hmtx'][glyph] == merged['hmtx'][cmap[cp]], f'Metrics mismatch {cp:X}'
    for pair, (original, glyph) in expected_ivs.items():
        assert outline(original, glyph) == outline(merged, ivs[pair]), f'IVS glyph mismatch {pair}'
        assert original['hmtx'][glyph] == merged['hmtx'][ivs[pair]], f'IVS metrics mismatch {pair}'
    for record in merged['name'].names:
        if record.nameID in (1, 3, 4, 6, 16):
            record.string = family.encode(record.getEncoding())
    # gjs performs all subsetting; fontTools merges layers and compresses them.
    # WOFF2's glyf transform is lossless. Verify coordinates and metrics by GID
    # because post-table glyph names may be reconstructed on the round-trip.
    path = work / f'bunsen-{style.lower()}-{bucket}.woff2'
    merged.flavor = 'woff2'
    merged.save(path)
    path.write_bytes(browser_compatible_woff2(path.read_bytes()))
    decoded = TTFont(path, recalcTimestamp=False)
    by_id = lambda f, mapping: {key: f.getGlyphID(value) for key, value in mapping.items()}
    assert by_id(decoded, decoded.getBestCmap()) == by_id(merged, cmap), 'WOFF2 cmap mismatch'
    assert by_id(decoded, variants(decoded)) == by_id(merged, ivs), 'WOFF2 IVS mismatch'
    for before, after in zip(merged.getGlyphOrder(), decoded.getGlyphOrder(), strict=True):
        assert merged['hmtx'][before] == decoded['hmtx'][after], 'WOFF2 metrics mismatch'
        assert merged['glyf'][before].getCoordinates(merged['glyf']) == decoded['glyf'][after].getCoordinates(decoded['glyf']), 'WOFF2 outline mismatch'
    decoded.close()
    data = path.read_bytes()
    name = f'{path.stem}-{digest(data)[:12]}.woff2'
    (output / name).write_bytes(data)
    unicode_range = ranges(set(expected) - latin_cps)
    css_family = f'Mikaki Bunsen {style}'
    record = {'family': css_family, 'weight': 400, 'range': unicode_range,
                  'codepoints': len(expected), 'variation_sequences': len(expected_ivs),
                  'file': name, 'bytes': len(data), 'sha256': digest(data)}
    rule = f"@font-face{{font-family:'{css_family}';font-style:normal;font-weight:400;font-display:swap;src:url('./{name}') format('woff2');unicode-range:{unicode_range}}}" if unicode_range else None
    if bucket == 'common':
        print(f'{family}: common chunk {len(data):,} bytes; all glyphs and IVS verified', flush=True)
    return record, rule

# Load the source glyph tables before forking so children expand in-memory
# glyph data rather than seeking shared file handles.
originals = {id(layer[0]): layer[0] for layers in records.values() for layer in layers}
for original in originals.values():
    original.getGlyphSet()
    original['hmtx']
    original['head']
css, files = [], []
with multiprocessing.get_context('fork').Pool(4) as pool:
    for record, rule in pool.imap(build_chunk, range(len(record_items))):
        if record is None:
            continue
        files.append(record)
        if rule:
            css.append(rule)
for style, filename in [('normal', 'InterVariable.woff2'), ('italic', 'InterVariable-Italic.woff2')]:
    data = (args.sources / filename).read_bytes()
    name = f'inter-{style}-{digest(data)[:12]}.woff2'
    (output / name).write_bytes(data)
    files.append({'family': 'Mikaki Latin', 'file': name, 'bytes': len(data), 'sha256': digest(data)})
    latin_range = ranges(TTFont(args.sources / filename).getBestCmap())
    css.insert(0, f"@font-face{{font-family:'Mikaki Latin';font-style:{style};font-weight:100 900;font-display:swap;src:url('./{name}') format('woff2');unicode-range:{latin_range}}}")
css.append(":root{--font-serif:'Mikaki Bunsen Mincho','Mikaki Latin','Hiragino Mincho ProN','Yu Mincho',serif;--font-sans:'Mikaki Bunsen Gothic','Mikaki Latin','Hiragino Sans','Yu Gothic',Meiryo,sans-serif;--font-body:var(--font-serif);font-family:var(--font-body);font-optical-sizing:auto;font-synthesis:weight}")
css.append(".font-mincho,[data-font-family='mincho']{--font-body:var(--font-serif);font-family:var(--font-body)}")
css.append(".font-gothic,[data-font-family='gothic']{--font-body:var(--font-sans);font-family:var(--font-body)}")
(output / 'fonts.css').write_text('\n'.join(css) + '\n')
reference_path = args.sources / 'acgj-acgjm.ttf'
reference = TTFont(reference_path)
target = set(cp for cp in reference.getBestCmap() if cp >= 0xf0000)
gap = {
    'reference': {
        'name': 'Additional Administrative Standard Mincho',
        'updated': '2026-08-18',
        'url': 'https://www.digital.go.jp/policies/local_governments/character-specification',
        'sha256': digest(reference_path.read_bytes()),
        'codepoints': len(target),
        'usage': 'Build-time coverage audit only; not bundled or used as a fallback',
    },
    'styles': {
        style: {'codepoints': len(coverage[style]),
                'variation_sequences': len(variation_coverage[style]),
                'administrative_covered': len(target & coverage[style]),
                'administrative_missing': len(target - coverage[style]),
                'missing_codepoints': [f'U+{cp:X}' for cp in sorted(target - coverage[style])]}
        for style in coverage
    },
}
(output / 'coverage.json').write_text(json.dumps(gap, indent=2) + '\n')
manifest = {'schema_version': 1, 'subsetter': {'repository': 'https://github.com/digital-go-jp/gjs',
             'commit': subprocess.check_output(['git', '-C', str(args.gjs), 'rev-parse', 'HEAD'], text=True).strip(),
             'wasm_sha256': digest((args.wasm_dir / 'font_subsetter_bg.wasm').read_bytes()),
             'lock_sha256': digest((ROOT / 'scripts/fonts.lock.json').read_bytes()),
             'compression': 'fontTools 4.65.0 WOFF2 glyf transform + Brotli 1.2.0'},
            'sources': families, 'files': files, 'coverage': 'coverage.json'}
(output / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
kept = {r['file'] for r in files}
for path in output.glob('*.woff2'):
    if path.name not in kept:
        path.unlink()
for source, destination in [('LICENSE', 'Bunsen-CC0.txt'), ('FONTLOG.txt', 'Bunsen-FONTLOG.txt')]:
    shutil.copyfile(args.gjs / 'dist-fonts' / source, output / destination)
shutil.copyfile(args.sources / 'Inter-OFL.txt', output / 'Inter-OFL.txt')
shutil.copyfile(ROOT / 'scripts/fonts-NOTICE.txt', output / 'NOTICE.txt')
for filename in ['IPA_Font_License_Agreement_v1.0.txt', 'Administrative-OFL.txt']:
    (output / filename).unlink(missing_ok=True)
print(f'Verified {len(files)} WOFF2 files, {sum(r["bytes"] for r in files):,} bytes', flush=True)
for style, result in gap['styles'].items():
    print(f'{style}: {result["administrative_covered"]}/{len(target)} additions; '
          f'{result["administrative_missing"]} missing', flush=True)
