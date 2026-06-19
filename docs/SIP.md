# DTrace & System Integrity Protection (SIP)

io-tracer-mac captures kernel I/O through **DTrace** (the `syscall` and `io`
providers). On a stock Mac, **System Integrity Protection (SIP)** restricts the
DTrace providers, so those probes fail to attach and the tracer can capture
nothing. You must allow DTrace once, before tracing.

## How to tell SIP is blocking DTrace

When SIP restricts DTrace, the probes fail to compile and each `dtrace`
subprocess exits immediately. The tracer reports this at startup:

```
[ERROR] [dtrace io.d] probe attach failed: dtrace: failed to compile script io.d: line 29: probe description io:::start does not match any probes. System Integrity Protection is on
[ERROR] DTrace could not attach its kernel probes: System Integrity Protection (SIP) is blocking the syscall/io providers, so NO filesystem or block-I/O events will be captured. ...
[ERROR] All DTrace streams exited at startup — the trace will contain no filesystem or block-I/O events. ...
```

You can also check the current status at any time (this does **not** require a
reboot):

```bash
csrutil status
```

A line such as `System Integrity Protection status: enabled.` means SIP is on.
On its own that does not prove DTrace is blocked (a custom configuration may
already permit it), but combined with the probe-attach errors above it confirms
SIP is the cause.

## Allowing DTrace

`csrutil` can only change SIP from **macOS Recovery** — it refuses to run from a
normal boot. Pick **one** of the two options below.

### Option A (recommended): keep SIP, permit only DTrace

This leaves every other SIP protection in place and relaxes only the DTrace
restriction.

1. **Boot into Recovery:**
   - **Apple silicon (M1/M2/M3/…):** shut down, then press and hold the **power
     button** until "Loading startup options" appears. Click **Options →
     Continue**.
   - **Intel:** restart and immediately hold **⌘ (Command) + R** until the Apple
     logo appears.
2. From the menu bar choose **Utilities → Terminal**.
3. Run:
   ```bash
   csrutil enable --without dtrace
   ```
4. Reboot back into macOS:
   ```bash
   reboot
   ```

After rebooting, `csrutil status` will report SIP as enabled but note that
**DTrace restrictions are disabled** (wording varies by macOS version).

### Option B: fully disable SIP

Use this only if Option A is unavailable on your macOS version. It turns off all
of SIP, so prefer Option A when possible.

1. Boot into Recovery (same steps as above).
2. **Utilities → Terminal**, then:
   ```bash
   csrutil disable
   ```
3. Reboot:
   ```bash
   reboot
   ```

## Re-enabling SIP afterwards

When you are done tracing and want to restore full protection, boot into
Recovery again and run:

```bash
csrutil enable
```

then reboot.

## Notes & caveats

- Changing SIP requires **physical access** and a reboot into Recovery; it
  cannot be done over SSH or from a normal login session.
- On Macs with **Activation Lock / MDM**, an administrator may have locked SIP;
  in that case `csrutil` in Recovery will refuse to change it.
- This tracer relies only on the `syscall`/`io` providers and never traces
  Apple-signed/"restricted" binaries, so `csrutil enable --without dtrace`
  (Option A) is sufficient — you do **not** need to fully disable SIP.
- After allowing DTrace you still need to run the tracer with **`sudo`**.
