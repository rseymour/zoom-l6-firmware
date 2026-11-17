#!/usr/bin/env python3
"""Execute stock and reordered USB capture paths without accessing a device."""
import hashlib
import json
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_CPU_ARM_MAX, UC_ARM_REG_FPEXC, UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_R11, UC_ARM_REG_PC,
)
from verify_pad_protocol import Machine, IMAGE, REGS, RETURN, ROOT, BIAS
from verify_usb_memory_providers import initialized, select, PROFILES
from verify_usb_ring_bounds import metadata_cases

sys.path.insert(0, str(ROOT / 'tools/firmware'))
from build_usb_reorder import (
    patch, digest, DSP_SOURCE, DSP_BASE, DSP_LENGTH, PACK_START, PACK_END, ORDER,
)

B = 0x20010a48
USB = 0x200180b4
STACK = 0x2003f000
RING = 0x81429800
STRIDE = 0xea600


class Native(Machine):
    def __init__(self, image):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_MAX)
        for address, size in ((0x80000000, 0x2000000), (0x20000000, 0x40000),
                              (DSP_BASE, 0x10000), (0x21000000, 0x40000)):
            self.uc.mem_map(address, size)
        self.uc.mem_write(0x80001000, image[0x200:0xb5ce4])
        self.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.hooks = {}
        self.installed = set()
        self.reached_return = False
        source, dest, length, helper = struct.unpack_from('<4I', image, 0x800a691c - BIAS)
        assert (source, dest, length) == (DSP_SOURCE, DSP_BASE, DSP_LENGTH)
        self.invoke(helper, [source, dest, length])
        if helper == 0x80079498:
            assert self.raw(DSP_BASE, DSP_LENGTH) == (
                image[DSP_SOURCE - BIAS:DSP_SOURCE - BIAS + DSP_LENGTH])
        else:
            assert helper == 0x80001994
            for at in (0x800a692c, 0x800a693c):
                source, dest, length, helper = struct.unpack_from('<4I', image, at - BIAS)
                self.invoke(helper, [source, dest, length])
        self.invoke(0x80001994, [0x800a6980, 0x801f5400, 0x3780])

    def invoke(self, address, args):
        for target in {RETURN, *self.hooks} - self.installed:
            self.uc.hook_add(UC_HOOK_CODE, self._hook, begin=target, end=target)
            self.installed.add(target)
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        for reg, value in zip(REGS, args):
            self.uc.reg_write(reg, value)
        for i, value in enumerate(args[4:]):
            self.put(STACK + 4 * i, value)
        self.reached_return = False
        self.uc.emu_start(address | 1, RETURN + 2, count=2000000)
        assert self.reached_return, f'No return at {self.uc.reg_read(UC_ARM_REG_PC):#x}'
        return self.uc.reg_read(REGS[0])

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value))

    def raw(self, address, size):
        return bytes(self.uc.mem_read(address, size))

    def window(self, start, end):
        def finish(uc, address, size, data):
            self.reached_return = True
            uc.emu_stop()
        hook = self.uc.hook_add(UC_HOOK_CODE, finish, begin=end, end=end)
        try:
            self.invoke(start, [])
        finally:
            self.uc.hook_del(hook)


def permute(data):
    return b''.join(data[frame * 48 + lane * 4:frame * 48 + lane * 4 + 4]
                    for frame in range(64) for lane in ORDER)


def marker_pack(image):
    m = Native(image)
    markers = [[0x4c000000 + lane * 0x10000 + frame * 17 for frame in range(64)]
               for lane in range(12)]
    source = struct.pack('<768I', *(value for lane in markers for value in lane))
    m.uc.mem_write(B + 0x40c8, source)
    m.uc.mem_write(USB - 16, b'\xa5' * (3072 + 32))
    m.uc.reg_write(UC_ARM_REG_R11, B)
    m.window(PACK_START, PACK_END)
    assert m.raw(B + 0x40c8, len(source)) == source
    assert m.raw(USB - 16, 16) == m.raw(USB + 3072, 16) == b'\xa5' * 16
    return m, m.raw(USB, 3072), markers


def transmit(m, floating, cursor, active=True):
    # Native ring claim/commit and both sample converters execute. Only kernel
    # critical sections and the already-negotiated USB state are fixtures.
    state, base, capacity = 0x808e2e54, 0x20003820, 128
    m.uc.mem_write(state, bytes(0x5c))
    for off, value in ((0x10, 48), (0x14, base), (0x18, capacity),
                       (0x24, cursor), (0x30, capacity)):
        m.put(state + off, value)
    m.uc.mem_write(state + 0x3c, b'\x01')
    m.uc.mem_write(0x808e2eb0, bytes([active]))
    m.uc.mem_write(0x802142b9, b'\x01')
    m.put(0x80214794, 0)
    m.put(0x80960020, 0x8006ff29)
    m.put(0x80960024, 0x80070191)
    m.hooks[0x800525d0] = lambda a: 0
    m.hooks[0x80053b88] = lambda a: 0
    # Execute the real format notification that installs the capture converter.
    m.hooks[0x8000c1b0] = lambda a: 0
    fmt = (1 if floating else 0) | (12 << 8) | ((32 if floating else 24) << 16) | (4 << 24)
    m.invoke(0x8003b3c8, [48000, 0x04200401, fmt])
    m.uc.mem_write(base, b'\xa5' * (capacity * 48))
    source = m.raw(USB, 3072)
    m.invoke(0x8003b280, [USB, 64])
    assert m.raw(USB, 3072) == source
    ring = m.raw(base, capacity * 48)
    if not active:
        assert ring == b'\xa5' * len(ring)
        assert m.raw(state + 0x24, 4) == struct.pack('<I', cursor)
        return None
    assert m.raw(state + 0x24, 4) == struct.pack('<I', (cursor + 64) % capacity)
    expected_ring = bytearray(b'\xa5' * len(ring))
    output = b''.join(ring[((cursor + frame) % capacity) * 48:
                          ((cursor + frame) % capacity) * 48 + 48] for frame in range(64))
    for frame in range(64):
        offset = ((cursor + frame) % capacity) * 48
        expected_ring[offset:offset + 48] = output[frame * 48:frame * 48 + 48]
    assert ring == bytes(expected_ring)
    return output


def playback(image, floating, cursor):
    m = Native(image)
    state, base, capacity = 0x808e2f80, 0x20000200, 128
    for off, value in ((0x10, 16), (0x14, base), (0x18, capacity),
                       (0x24, cursor), (0x30, capacity)):
        m.put(state + off, value)
    m.uc.mem_write(state + 0x3c, b'\x01')
    m.uc.mem_write(state + 0x48, b'\x01\x01')
    m.uc.mem_write(0x802142b9, b'\x01')
    m.put(0x80214794, 0)
    m.put(0x80960018, 0x8006ffb1)
    m.put(0x8096001c, 0x800701f9)
    for fn in (0x800525d0, 0x80053b88, 0x8000c1b0):
        m.hooks[fn] = lambda a: 0
    m.hooks[0x800707f8] = lambda a: 1
    fmt = (1 if floating else 0) | (4 << 8) | ((32 if floating else 24) << 16) | (4 << 24)
    m.invoke(0x8003b3c8, [48000, fmt, 0x04200c01])
    values = [(frame * 4 + lane - 127) * 1024 for frame in range(64) for lane in range(4)]
    source = struct.pack('<256f' if floating else '<256i',
                         *([v / 2**31 for v in values] if floating else values))
    for frame in range(64):
        m.uc.mem_write(base + ((cursor + frame) % capacity) * 16,
                       source[frame * 16:frame * 16 + 16])
    m.invoke(0x8003b168, [0x20017cb4, 64])
    assert m.raw(0x20017cb4, 1024) == struct.pack('<256f', *values)
    assert m.raw(state + 0x24, 4) == struct.pack('<I', (cursor + 64) % capacity)
    assert m.raw(base, capacity * 16) == bytes(capacity * 16)
    return m.raw(0x20017cb4, 1024)


def full_dsp(image):
    m = Native(image)
    m.hooks[0x80006248] = lambda a: 0
    m.hooks[0x80074440] = lambda a: 0
    m.invoke(0x80011920, [48000])
    for lane in range(10):
        m.uc.mem_write(B + 0x5864 + lane * 16,
                       struct.pack('<4I', 0x21010000 + lane * 0x1000, 128, 127, 0))
    m.put(B + 0x53e8, 128)
    m.put(B + 0x53f8, 128)
    # A nonzero synthetic mix and distinct dry inputs exercise both sources.
    m.uc.mem_write(B + 0x5e34, struct.pack('<20f', *([1] + [0] * 9 + [0, 1] + [0] * 8)))
    m.uc.mem_write(0x2000fa48, struct.pack('<768i', *(
        (lane + 1) * (frame - 32) * (1 << 18)
        for lane in range(12) for frame in range(64))))
    snapshots = []
    for block in range(3):
        m.invoke(0x2022a790, [])
        usb = m.raw(USB, 3072)
        if image == IMAGE:
            lanes = [struct.unpack('<64f', m.raw(
                RING + lane * STRIDE + (block % 2) * 256, 256)) for lane in range(12)]
            expected = struct.pack('<768f', *(lanes[lane][frame] * 2**31
                for frame in range(64) for lane in (10, 11, *range(10))))
            assert usb == expected
            assert all(any(lane) for lane in lanes)
        snapshots.append((usb, m.raw(B, 0x63b0),
                          b''.join(m.raw(RING + lane * STRIDE, 512) for lane in range(12)),
                          m.raw(0x20017cb4, 1024), m.raw(0x20010648, 1024)))
    return snapshots


def main():
    candidate, edits = patch(IMAGE)
    rows = []
    profiles = initialized()
    select(profiles, PROFILES[4], 0)
    formats = metadata_cases(profiles)
    assert {a for rate, a, b in formats} == {(0, 4, 24, 4), (1, 4, 32, 4)}
    assert {b for rate, a, b in formats} == {(0, 12, 24, 4), (1, 12, 32, 4)}
    assert {rate for rate, a, b in formats} == {48000}
    rows.append('stock 089e profile confirms 48 kHz, float32 and PCM24 in four-byte slots')
    stock, old, markers = marker_pack(IMAGE)
    changed, new, _ = marker_pack(candidate)
    expected = struct.pack('<768I', *(markers[lane][frame]
                                     for frame in range(64) for lane in range(12)))
    assert old == expected and new == permute(old) and new != old
    rows.append('all twelve distinct channels and 64 frames reordered exactly')
    for floating in (False, True):
        for cursor in (0, 64, 96, 127):
            before = transmit(stock, floating, cursor)
            after = transmit(changed, floating, cursor)
            assert after == permute(before) and any(before)
        transmit(changed, floating, 96, active=False)
        rows.append(f'{"float32" if floating else "PCM24"} transmit, four ring positions and inactive USB')
        for cursor in (0, 96):
            assert playback(IMAGE, floating, cursor) == playback(candidate, floating, cursor)
        rows.append(f'{"float32" if floating else "PCM24"} four-channel USB playback unchanged, including wrap')
    for before, after in zip(full_dsp(IMAGE), full_dsp(candidate)):
        assert after[0] == permute(before[0]) and before[0] != bytes(3072)
        assert after[1:] == before[1:]
    rows.append('full DSP, three blocks through recorder wrap; input/master identities verified against recorder')
    rows.append('mixer state, all twelve recorder lanes, physical outputs and USB return buffers unchanged')
    try:
        patch(candidate)
    except ValueError:
        rows.append('already-patched input refused')
    else:
        raise AssertionError('Modified input accepted')
    report = dict(passed_groups=len(rows), checks=rows, source_sha256=digest(IMAGE),
                  candidate_sha256=hashlib.sha256(candidate).hexdigest(), edits=edits,
                  device_access=False, limitations=[
                      'Synthetic ADC, mixer coefficients and negotiated USB state; effects idle',
                      'ARM MAX executes stock DSP; no timing, DMA, USB host or updater emulation',
                      'Normal DSP callback only; alternate callback modes not exercised',
                      'Recorder rings compared, not physical SD writes or WAV files'])
    out = ROOT / 'analysis/usb_reorder_verification.json'
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    if not __debug__:
        sys.exit('Verification requires assertions enabled')
    main()
