# Frida capture (v1) -- image dependency

`modules/auxiliary/frida.py` drives guest-local dynamic instrumentation via
[`frida-inject`](https://github.com/frida/frida/releases), a standalone
prebuilt binary. It expects that binary to already exist, executable, at:

```
/data/local/tmp/frida-inject
```

on the guest image. This is **not** fetched, installed, or baked into any
snapshot by this code -- same class of out-of-band image dependency as
`analyzer/linux/modules/auxiliary/tracee.py`'s requirement that Docker and
the `aquasec/tracee` image already be present on the Linux guest.

To provision it: download `frida-inject-<version>-android-x86_64.xz` from
the frida release matching this repo's compiled agent (see
`frida_src/agent-src.js` and the note below), decompress it, `chmod 755`,
and place it at that path on the golden image before taking the guest's
clean snapshot. The 110MB+ binary is intentionally not committed to this
repository.

If the binary is missing, `Frida.start()` logs a warning and disables
itself. **The analysis still completes normally** -- install/launch
reporting is unaffected. Missing Frida is not a failed analysis.

Host processing (`modules/processing/android_frida.py`) reads
`logs/frida.log` into `results["frida"]`. Enable it in `processing.conf`:

```
[android_frida]
enabled = yes
platform = android
```

No signatures read this key. Events are not merged into `results["behavior"]`.

## No frida-server

Earlier design notes for this feature assumed a `frida-server` daemon
(the client/server model most Frida documentation leads with). Live
testing on this guest found `frida-inject` performs its own injection
without any running server -- it was dropped from this design once that
was confirmed, rather than shipping a component nothing here uses.

## Late attach

The `apk` package launches the sample before it can tell this auxiliary
the PID. The first `Activity.onResume` has usually already returned.
v1 handles that in two ways:

1. The compiled agent enumerates live `Activity` instances and emits
   `onResume` with `args_preview: ["<already-resumed>"]`.
2. A few seconds after inject, the auxiliary sends `KEYCODE_HOME` and a
   launcher `monkey` so a real `onResume` fires under the hook.

## Why the compiled agent is checked in, not built at guest time

`frida_src/agent-src.js` is the hook source: `import Java from
"frida-java-bridge"`, per Frida 17's split of the Java bridge out of the
core runtime. Neither the CAPE host nor this Android guest has `node`, so
the bundle is compiled once, offline, and the *compiled* output
(`data/frida-agent.js`) is what actually ships and runs. To rebuild it
after editing the source:

```
npm install frida-compile frida-java-bridge
npx frida-compile analyzer/android/modules/auxiliary/frida_src/agent-src.js \
    -o analyzer/android/modules/auxiliary/data/frida-agent.js
```

## Sample UIs that wait for a click

Some APKs (RootBeer sample included) only run their interesting Java on a
FloatingActionButton click. The compiled agent clicks the first Material/Support
FAB it can find about five seconds after attach, and logs `File.exists` only
for paths that look like su/magisk/busybox.
