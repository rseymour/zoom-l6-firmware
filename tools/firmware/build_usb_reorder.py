#!/usr/bin/env python3
"""Build an experimental USB-input reorder from stock L6 v1.10, offline only."""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
from build_deployment_probe import (
    ROOT, SOURCE, STOCK_SHA, CHECKSUM_OFFSET, digest, validate, write_manifest,
)

BIAS = 0x80000e00
DSP_SOURCE = 0x800a9408
DSP_BASE = 0x20220000
DSP_LENGTH = 0xd6dc
PACK_START = 0x20229538
PACK_END = 0x20229b74
ORDER = (*range(2, 12), 0, 1)
OUT = ROOT / 'deployment/usb_reorder'


def movw(register, immediate):
    return struct.pack('<HH',
        0xf240 | (immediate >> 12) | (((immediate >> 11) & 1) << 10),
        (((immediate >> 8) & 7) << 12) | (register << 8) | (immediate & 255))


def dsp_patches(stock):
    """Byte-checked source selections, applied before DSP compression."""
    if digest(stock) != STOCK_SHA:
        raise ValueError('USB reorder requires the exact stock L6 v1.10 image')
    offset = DSP_SOURCE - BIAS + PACK_START - DSP_BASE
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    instructions = list(md.disasm_lite(stock[offset:offset + PACK_END - PACK_START], PACK_START))
    sources = [(pc, size, operands) for pc, size, op, operands in instructions
               if op == 'movw' and 0x4104 <= int(operands.split('#')[1], 0) <= 0x4c04]
    if len(sources) != 12:
        raise ValueError('Expected twelve USB source selections')
    patches = []
    for channel, ((pc, size, operands), source) in enumerate(zip(sources, ORDER)):
        register = 0 if channel == 0 else 1
        before = 0x4104 + channel * 0x100
        after = 0x4104 + source * 0x100
        if size != 4 or operands != f'r{register}, #{before:#x}':
            raise ValueError(f'Unexpected USB source instruction at {pc:#x}')
        file_offset = DSP_SOURCE - BIAS + pc - DSP_BASE
        old, new = movw(register, before), movw(register, after)
        if stock[file_offset:file_offset + 4] != old or list(md.disasm_lite(new, pc)) != [
                (pc, 4, 'movw', f'r{register}, #{after:#x}')]:
            raise ValueError(f'USB source encoding mismatch at {pc:#x}')
        patches.append(dict(site=pc, bytes=4, original=old.hex(), patch=new.hex(),
                            adapter=f'usb_source_{channel + 1}',
                            source_file_offset=file_offset,
                            destination_slot=channel + 1, source_slot=source + 1))
    return patches


def patch(stock):
    if not __debug__:
        raise RuntimeError('Refusing to patch with Python assertions disabled')
    if digest(stock) != STOCK_SHA:
        raise ValueError('USB reorder requires the exact stock L6 v1.10 image')
    validate(stock)
    assert struct.unpack_from('<4I', stock, 0x800a691c - BIAS) == (
        DSP_SOURCE, DSP_BASE, DSP_LENGTH, 0x80079498)
    candidate = bytearray(stock)
    edits = []
    for q in dsp_patches(stock):
        file_offset = q['source_file_offset']
        old, new = bytes.fromhex(q['original']), bytes.fromhex(q['patch'])
        candidate[file_offset:file_offset + 4] = new
        edits.append(dict(runtime_address=hex(q['site']), file_offset=hex(file_offset),
                          before=old.hex(), after=new.hex(),
                          stock_slot=q['destination_slot'], new_source_slot=q['source_slot']))
    struct.pack_into('>I', candidate, CHECKSUM_OFFSET, sum(candidate[0x200:]) & 0xffffffff)
    candidate = bytes(candidate)
    validate(candidate)
    allowed = set(range(CHECKSUM_OFFSET, CHECKSUM_OFFSET + 4))
    for edit in edits:
        allowed.update(range(int(edit['file_offset'], 16), int(edit['file_offset'], 16) + 4))
    changed = {i for i, (a, b) in enumerate(zip(stock, candidate)) if a != b}
    assert changed <= allowed and len(candidate) == len(stock)
    assert candidate[0x285200:] == stock[0x285200:]
    return candidate, edits


def build():
    stock = SOURCE.read_bytes()
    candidate, edits = patch(stock)
    output = OUT / 'L6.BIN'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_bytes() != candidate:
        raise RuntimeError(f'Refusing to overwrite a different image: {output}')
    output.write_bytes(candidate)
    assert output.read_bytes() == candidate
    report = dict(
        purpose='USB capture inputs 1-10 first, master L/R last; no other features',
        source_sha256=STOCK_SHA, sha256=digest(candidate), bytes=len(candidate),
        image=str(output.relative_to(ROOT)), edits=edits,
        changed_bytes=sum(a != b for a, b in zip(stock, candidate)),
        deployment_status='Experimental; see docs/usb-reorder.md for dated testing limits',
        unchanged=['USB descriptors and playback routing', 'SD recording routing',
                   'Mixer processing and physical outputs', 'BOOT, PANEL and AUDIOGUIDE',
                   'Image size, version and all code outside the twelve source immediates'],
        limitations=['Only the normal DSP USB packing path is changed',
                     'Offline verification is not a hardware timing or updater test',
                     'Applications using the first pair will receive inputs 1/2, not the master'])
    write_manifest(OUT / 'manifest.json', report)
    (OUT / 'SHA256SUMS').write_text(f'{digest(candidate)}  L6.BIN\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Refusing to build with Python assertions disabled')
    build()
