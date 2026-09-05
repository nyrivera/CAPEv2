import json
import logging
import os

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

__author__ = "nyrivera"
__version__ = "1.0.0"


class AndroidFrida(Processing):
    """Parses the Android guest's Frida capture log (analyzer/android/modules/auxiliary/frida.py)
    into a flat list of hook events under results["frida"].

    This is a sibling report section, not part of results["behavior"] --
    see modules/processing/tracee.py for the existing precedent of a
    dynamic-instrumentation source that reports under its own key instead
    of feeding the Windows-oriented behavior/signature pipeline. No
    signature currently reads this key.
    """

    order = 2

    def run(self):
        self.key = "frida"
        logpath = os.path.join(self.analysis_path, "logs", "frida.log")

        if not os.path.exists(logpath):
            return {"status": "not_captured", "events": []}

        events = []
        with open(logpath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    log.warning("Skipping malformed frida log line")
                    continue
                events.append(event)

        return {"status": "captured", "events": events}
