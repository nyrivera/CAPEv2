import json
import logging
import os
import subprocess
import time

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile, append_buffer_to_host

log = logging.getLogger(__name__)

INJECT_BIN = "/data/local/tmp/frida-inject"
AGENT_JS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "frida-agent.js")
EVENT_LOG_PATH = os.path.join(os.environ.get("TMPDIR", "/data/local/tmp"), "frida_events.log")

# Set by the "apk" package (lib/core/packages.py -> modules/packages/apk.py)
# once it has actually launched the sample and discovered its PID -- this
# module has no PID of its own to attach to until that happens, and the
# analyzer wires auxiliary modules up before the package runs (see
# analyzer.py's Analyzer.run()). This is the "package hook" half of the
# design: a single, defensive call-out, not a rewrite of Apk.
_target_package = None
_target_pid = None


def notify_target(package_name, pid):
    """Record the launched sample's package name and PID for the Frida
    auxiliary to pick up on its next polling tick.

    Safe to call even if this module or frida-inject is unavailable --
    this only ever sets module globals, no I/O.
    """
    global _target_package, _target_pid
    _target_package = package_name
    _target_pid = pid


class Frida(Auxiliary):
    """Guest-local dynamic instrumentation via a prebuilt frida-inject binary.

    Mirrors analyzer/linux/modules/auxiliary/tracee.py: this produces a raw
    JSON-lines log uploaded to the host as a plain log file, parsed by a
    separate host-side processing module into its own report key. It does
    NOT feed modules/processing/behavior.py or any signature -- see the
    design note in the PR this shipped with for why.

    Deployment note: frida-inject is an ~110MB prebuilt binary (from
    https://github.com/frida/frida/releases, asset
    frida-inject-<ver>-android-x86_64.xz) that this module expects to
    already exist, executable, at /data/local/tmp/frida-inject on the
    guest image -- the same class of out-of-band image dependency as
    tracee's Docker+aquasec/tracee container. It is intentionally NOT
    fetched, staged, or baked into any snapshot by this code, and is never
    committed to this repository.

    If the binary is missing, start() logs a warning and disables the
    module; the analysis still completes normally. Missing Frida is not a
    failed analysis.

    No frida-server is used or required. frida-inject performs its own
    injection without a running server -- see frida_src/agent-src.js and
    the module docstring for how the compiled agent gets there.
    """

    priority = 0

    def __init__(self, options=None, analyzer=None):
        super().__init__(options or {}, analyzer)
        self.available = False
        self.proc = None
        self.injected_pid = None
        self.injection_attempted = False

    def start(self):
        if not (os.path.isfile(INJECT_BIN) and os.access(INJECT_BIN, os.X_OK)):
            log.warning("Frida auxiliary disabled: %s not present or not executable on this guest", INJECT_BIN)
            self.available = False
            return
        if not os.path.isfile(AGENT_JS):
            log.warning("Frida auxiliary disabled: compiled agent missing at %s", AGENT_JS)
            self.available = False
            return
        self.available = True
        log.info("Frida auxiliary ready, waiting for a target PID")

    def get_pids(self):
        """Polled once a second by analyzer.py's main loop. Used here purely
        as a timing hook to notice the target PID as soon as the package
        hands it off -- this module does not itself track new PIDs.
        """
        if self.available and not self.injection_attempted and _target_pid:
            self._inject(_target_pid, _target_package)
        return []

    def _inject(self, pid, package_name):
        self.injection_attempted = True
        try:
            command = ["sh", "-c", f'exec "$1" -p "$2" -s "$3" > "$4" 2>&1', "sh", INJECT_BIN, str(pid), AGENT_JS, EVENT_LOG_PATH]
            self.proc = subprocess.Popen(command)
            self.injected_pid = pid
            log.info("Frida injected into pid %s (package %s)", pid, package_name)
        except Exception as e:
            log.warning("Failed to start frida-inject against pid %s: %s", pid, e)
            self.proc = None

    def stop(self):
        if not self.proc:
            return
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self._upload_events()

    def _upload_events(self):
        """frida-inject fully buffers its stdout when it isn't a tty, so
        nothing is available to read until the process exits (see the
        design note for how this was confirmed). There is therefore no
        live-tailing thread here, unlike tracee's Docker log -- events are
        only available once stop() has terminated the injected process.
        """
        if not os.path.exists(EVENT_LOG_PATH):
            return

        events = []
        try:
            with open(EVENT_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        frame = json.loads(line)
                    except ValueError:
                        continue
                    if frame.get("type") != "send":
                        continue
                    payload = frame.get("payload")
                    if not isinstance(payload, dict):
                        continue
                    payload["package"] = _target_package
                    events.append(payload)
        except Exception as e:
            log.warning("Failed to read Frida event log: %s", e)
            return

        if not events:
            return

        try:
            nc = NetlogFile()
            nc.init("logs/frida.log")
            for event in events:
                append_buffer_to_host((json.dumps(event) + "\n").encode(), nc)
            nc.close()
        except Exception as e:
            log.warning("Failed to upload Frida events to host: %s", e)
