# USB input order

This optional patch for the original LiveTrak L6 moves the stereo master
behind the ten numbered inputs sent to the computer. It is for stock v1.10,
not the L6max. It can be built with the overdub and stereo AUX features, or
on its own.

The USB reorder patch is by Rich Seymour, using Thade O'Connor's firmware
research, container tools and emulator tests.

The new USB capture order is inputs 1 through 10, followed by MASTER L/R on
11/12. Left and right keep their order. USB playback from the computer, the
physical outputs and SD recording routing are not changed. Apps that capture
the first stereo pair will receive inputs 1/2 instead of the master, and saved
DAW input assignments may need updating.

## Status

On 17 November 2026, Rich Seymour reported checking numbered inputs, onboard
FX and level controls on an L6 with the reorder-only patch. The USB format
was not recorded. SD recording, master 11/12, USB playback and long-running
operation have not been documented as checked on hardware.

The combined image with overdub and stereo AUX has not been tested on
hardware. Treat both variants as experimental.

On the same date, the reorder-only verifier passed nine offline groups.
The combined release verifier passed seven groups, including the original
reset/scatter loader and both USB sample formats. The full release regression
passed 53 groups with this option's checks included; the default v0.3.1 image
kept its published hash.

This is unofficial firmware. Zoom's firmware licence restricts modification
and reverse engineering. The upstream project reports recovery tests with its
own broken firmware, but those are not a guarantee of recovery for this image.

## Build with overdub and stereo AUX

Follow [setup](setup.md) to obtain the stock firmware and prepare the Python
environment, then run:

```sh
python tools/firmware/build_release.py --usb-inputs-first
```

The result is `release/0.3.1-usb-inputs-first/L6.BIN`, with its own manifest,
checksum file and recipe. The flag is off by default. It does not replace
the pinned release, change the browser patcher's recipes or add a runtime
switch on the mixer. The firmware version displayed by the L6 is unchanged.

The combined build applies the twelve source edits before the DSP is
compressed, alongside the two linked AUX limiter patches. It uses the same
overdub/AUX code as the default release. Its output hash differs from the
reorder-only image below.

Verify the combined build with:

```sh
PYTHONPATH=tests/emulation:tools/firmware .venv/bin/python -m verify_usb_reorder_release
```

The check compares it with the pinned default release, executes the original
reset and scatter loading, checks capture and playback in both USB formats,
and compares recorder and physical-output buffers through three DSP blocks.
It also rebuilds the recipe and checks that the two CLI outputs are separate
and the hosted patcher files stay unchanged. These are offline checks.

## Build and verify the reorder-only patch

Follow [setup](setup.md) to obtain the stock firmware and prepare the Python
environment. Only Capstone, Unicorn and pyelftools are needed for these checks;
there is no compiler or Ghidra requirement.

From the repository root, run:

```sh
PYTHONPATH=tests/emulation:tools/firmware .venv/bin/python -m verify_usb_reorder
PYTHONPATH=tools/firmware .venv/bin/python -m build_usb_reorder
```

The verifier writes `analysis/usb_reorder_verification.json`. The builder
refuses any input other than the exact stock v1.10 image, including an
already-patched image. It writes:

- `deployment/usb_reorder/L6.BIN`
- `deployment/usb_reorder/manifest.json`
- `deployment/usb_reorder/SHA256SUMS`

Nothing in either command opens USB or MIDI devices or writes to a card.
This command does not add overdub, take history or stereo AUX.

Reorder-only SHA256:

```text
06d188db803e738dece04b0bf73f0e921c9fab95c9f460971d4f62f14bdfef9b
```

## Implementation

The normal DSP callback at `0x2022a790` eventually runs the USB interleaver
at `0x20229538` through `0x20229b74`. That interleaver copies twelve planar
64-frame buffers into the interleaved USB staging buffer at `0x200180b4`.
The original order is master left, master right, then the ten input lanes.
The input and master identities were checked against the recorder's twelve
lanes while executing the complete DSP callback.

The reorder changes the source addresses in twelve existing MOVW instructions.
The source-lane permutation, using zero-based indices, is
`2,3,4,5,6,7,8,9,10,11,0,1`. These are address changes, not new processing
instructions, extra copies, hooks or task allocations.

For the reorder-only build, the stock scatter-loader entry at `0x800a691c` copies this code from
`0x800a9408` to `0x20220000`. The builder patches that existing source span,
without repacking or replacing the loader. Sixteen file bytes change.
The package checksum is recalculated and happens to stay the same because
the instruction-byte changes have a zero net sum. All other firmware bytes,
including descriptors, versions, panel code and voice data, are unchanged.
The manifest lists every patched instruction and file offset.

The common USB capture wrapper at `0x8003b280`, its float/PCM converters and
its transmit-ring claim and commit routines remain stock. The normal USB
profile advertises 48 kHz float32 and PCM24, both in four-byte sample slots.
USB descriptors have no individual channel-name strings in the inspected
normal profile, so this patch reorders the actual samples rather than names.

## Verification

The focused verifier checks:

- Distinct markers for all twelve channels and every frame in a block.
- Exact USB transmit permutation in float32 and PCM24, including split writes
  across the end of the ring and inactive USB.
- Unchanged four-channel USB playback in both formats, including ring wrap.
- Three complete normal DSP callbacks through the recorder ring's wrap.
  The mixer state, all twelve recorder lanes, physical-output buffers and USB
  return buffers match stock while the capture samples are reordered.
- Loading the actual patched code with the original copy routine and rejection
  of an already-patched source image.

The existing USB ring suite also passed 22 groups covering 600 format/timing
cases and 616 wrap/inactive cases. It can be rerun with:

```sh
PYTHONPATH=tests/emulation:tools/firmware .venv/bin/python -m verify_usb_ring_bounds
```

The tests use synthetic audio inputs, negotiated USB state and kernel
critical-section effects. Effects processing is idle. ARM MAX supplies the
instructions used by the stock DSP; it is not a hardware timing model.
Alternate audio callbacks are not changed or exercised by the focused suite.
The SD comparison is of recorder buffers, not filesystem or physical card IO.

Before normal use of the combined image, a controlled hardware trial still
needs to confirm each numbered input and master pair, both USB formats,
simultaneous SD recording, USB reconnects, unchanged playback and analog
output, overdubbing and stereo AUX.
