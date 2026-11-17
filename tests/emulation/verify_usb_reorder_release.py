#!/usr/bin/env python3
"""Check the optional USB order on the combined release. No device access."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn import arm_const as A
from verify_usb_reorder import marker_pack, transmit, playback, full_dsp, permute
from build_master_trial import trial, MODES
from build_deployment_probe import ROOT, SOURCE, digest, validate
import recipe as recipes


def main():
    baseline, wav, before, original = trial('release')
    candidate, reordered_wav, after, changed = trial('release', usb_inputs_first=True)
    assert digest(baseline) == MODES['release']['sha']
    assert candidate != baseline and wav == reordered_wav
    assert after['expected_sha256'] is None and after['usb_inputs_first']
    assert after['version'] == before['version'] + '-usb-inputs-first'
    assert after['patches'] == before['patches']
    assert changed['pack']['code'] == original['pack']['code']
    old_dsp, new_dsp = original['pack']['dsp'], changed['pack']['dsp']
    patches = [q for q in after['DSP_patches'] if q['adapter'].startswith('usb_source_')]
    expected = bytearray(old_dsp)
    for q in patches:
        offset = q['site'] - 0x20220000
        assert old_dsp[offset:offset + 4] == bytes.fromhex(q['original'])
        expected[offset:offset + 4] = bytes.fromhex(q['patch'])
    assert len(patches) == 12 and bytes(expected) == new_dsp
    assert sum(a != b for a, b in zip(old_dsp, new_dsp)) == 16
    assert [q for q in after['DSP_patches'] if q not in patches] == before['DSP_patches']
    validate(candidate)

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.ctl_set_cpu_model(A.UC_CPU_ARM_CORTEX_M7)
    for address, size in ((0x80000000, 0x2000000), (0x20000000, 0x40000),
                          (0x21000000, 0x40000), (0, 0x1000),
                          (0x20210000, 0x20000), (0xe000e000, 0x1000)):
        uc.mem_map(address, size)
    uc.mem_write(0x80001000, candidate[0x200:0xb5ce4])
    reached = []
    hook = uc.hook_add(UC_HOOK_CODE, lambda uc, a, n, data: reached.append(a) or uc.emu_stop(),
                         begin=0x80067a60, end=0x80067a60)
    uc.emu_start(0x80001401, 0x80067a62, count=100000000)
    uc.hook_del(hook)
    assert reached == [0x80067a60]
    assert bytes(uc.mem_read(0x20220000, len(new_dsp))) == new_dsp
    assert bytes(uc.mem_read(after['code_start'], len(changed['pack']['code']))) == changed['pack']['code']

    stock, old, _ = marker_pack(baseline)
    reordered, new, _ = marker_pack(candidate)
    assert new == permute(old)
    for floating in (False, True):
        for cursor in (0, 64, 96, 127):
            assert transmit(reordered, floating, cursor) == permute(transmit(stock, floating, cursor))
        assert transmit(reordered, floating, 96, active=False) is None
        for cursor in (0, 96):
            assert playback(baseline, floating, cursor) == playback(candidate, floating, cursor)
    for old, new in zip(full_dsp(baseline), full_dsp(candidate)):
        assert new[0] == permute(old[0]) and any(old[0])
        assert old[1:] == new[1:]
    recipe = recipes.make(SOURCE.read_bytes(), candidate, changed['pack'], after['version'])
    assert recipes.rebuild(SOURCE.read_bytes(), recipe) == candidate
    assert recipes.stock_bytes(SOURCE.read_bytes(), recipe) == 0

    shelf = ROOT / 'patcher/recipes'
    published = {p.name: p.read_bytes() for p in shelf.iterdir() if p.is_file()}
    env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT/'tools/firmware'),
                                                     str(ROOT/'tests/emulation'))))
    with tempfile.TemporaryDirectory() as directory:
        for flag, image, report in (([], baseline, before), (['--usb-inputs-first'], candidate, after)):
            result = subprocess.run([sys.executable, str(ROOT/'tools/firmware/build_release.py'),
                                     '--out', directory, *flag], env=env, text=True, capture_output=True)
            assert result.returncode == 0, result.stdout + result.stderr
            summary = json.loads(result.stdout.strip().splitlines()[-1])
            assert summary['pinned'] == (not flag)
            out = Path(directory) / report['version']
            assert (out/'L6.BIN').read_bytes() == image
            assert recipes.rebuild(SOURCE.read_bytes(), json.loads((out/'recipe.json').read_text())) == image
        assert {p.name: p.read_bytes() for p in shelf.iterdir() if p.is_file()} == published
    print(json.dumps(dict(passed=True, groups=7, baseline_sha256=digest(baseline),
                          reordered_sha256=digest(candidate), device_access=False,
                          checks=['default pinned release unchanged', 'only twelve extra DSP source edits',
                                  'original reset and scatter loading', 'capture and playback in both formats',
                                  'full DSP and recorder isolation', 'recipe rebuild without stock bytes',
                                  'CLI isolates variant and preserves hosted patcher recipes'])))


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Verification requires assertions enabled')
    main()
