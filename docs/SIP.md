# Letting the tracer run: a quick guide to System Integrity Protection (SIP)

To watch your Mac's file and disk activity, this tool uses a built-in macOS
feature called **DTrace**. By default, a security feature called **System
Integrity Protection (SIP)** keeps DTrace switched off. So before you can record
a trace, you need to give DTrace permission **once**. After that, it stays on
until you change it back.

This guide walks you through it in plain steps. You'll need to restart your Mac
twice and type one command — no prior experience required.

> **Is this safe?** You're not turning your Mac's security off. The recommended
> option below keeps every other protection in place and only unlocks the
> tracing feature. You can switch it fully back on at any time (see
> [Turning protection back on](#turning-protection-back-on)).

---

## How do I know I need this?

If you try to record a trace and SIP is in the way, the tool **stops right away**
and prints a message like this:

```
Stopping: DTrace could not attach any probes. If System Integrity Protection
(SIP) is enabled it must be configured to allow DTrace first ...
```

If you see that, follow the steps below. (If you're curious, you can check your
Mac's current setting any time by opening the **Terminal** app and running
`csrutil status` — no restart needed.)

---

## Step-by-step: allow DTrace

You make this change from a special startup screen called **Recovery**. The
normal desktop won't let you change it.

### 1. Start up in Recovery mode

**If your Mac has Apple silicon** (most Macs from 2020 onward — anything with an
M1, M2, M3, or newer chip):

1. Choose the **Apple menu** (top-left of the screen) → **Shut Down** and wait
   for it to turn off completely.
2. Press and **hold the power button** until you see "Loading startup options".
3. Click **Options**, then **Continue**.

**If your Mac has an Intel processor** (older Macs):

1. Choose the **Apple menu** (top-left of the screen) → **Restart**.
2. Immediately press and hold **Command (⌘) + R** until the Apple logo appears,
   then let go.

Not sure which one you have? Choose the **Apple menu** → **About This Mac**. If it lists
a "Chip" starting with **Apple M…**, it's Apple silicon; if it lists a
"Processor" with **Intel**, it's Intel.

### 2. Open Terminal

In the Recovery screen, click **Utilities** in the menu bar at the top, then
choose **Terminal**.

### 3. Type the command

In the Terminal window, type this exactly and press **Return**:

```
csrutil enable --without dtrace
```

This keeps your Mac's security on and only unlocks tracing. You should see a
message confirming the change.

### 4. Restart back to your desktop

Type this and press **Return**:

```
reboot
```

Your Mac will start up normally. That's it — you can now record traces (remember
to run the tracer with `sudo`, as the instructions show).

---

## Turning protection back on

When you're finished tracing and want to restore the default security setting,
just repeat the steps above, but in **step 3** type this instead:

```
csrutil enable
```

Then `reboot`. Done.

---

## If something doesn't work

- **The command says it can't make the change.** Make sure you started up in
  **Recovery** (steps in section 1) — the command only works there, not from
  your normal desktop.
- **You're connecting remotely (e.g. over SSH).** This change can't be done
  remotely; it needs you to be at the Mac to use the Recovery screen.
- **Your Mac is managed by a school or company.** Some organizations lock this
  setting. If the command is refused even in Recovery, ask your IT administrator.

---

### A note for the technically curious

The recommended `csrutil enable --without dtrace` relaxes only DTrace and leaves
the rest of SIP intact, which is all this tracer needs — it uses just the
`syscall` and `io` providers and never inspects Apple-signed/"restricted"
programs. There's also a `csrutil disable` command that turns SIP off entirely,
but you shouldn't need it; prefer the `--without dtrace` form above.
