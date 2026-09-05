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

## No frida-server

Earlier design notes for this feature assumed a `frida-server` daemon
(the client/server model most Frida documentation leads with). Live
testing on this guest found `frida-inject` performs its own injection
without any running server -- it was dropped from this design once that
was confirmed, rather than shipping a component nothing here uses.

## Why the compiled agent is checked in, not built at guest time

`frida-src/agent-src.js` is the hook source: `import Java from
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
