import json
import os

from modules.processing.android_frida import AndroidFrida


def make_processor(tmp_path, log_lines=None):
    processor = AndroidFrida()
    processor.set_path(str(tmp_path))
    if log_lines is not None:
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        with open(logs_dir / "frida.log", "w") as f:
            for line in log_lines:
                f.write(json.dumps(line) + "\n")
    return processor


class TestAndroidFrida:
    def test_no_log_file(self, tmp_path):
        processor = make_processor(tmp_path)
        result = processor.run()
        assert result == {"status": "not_captured", "events": []}

    def test_parses_events(self, tmp_path):
        events_in = [
            {"ts": 1.0, "pid": 100, "package": "com.example.app", "class": None, "method": None, "hook_status": "ok"},
            {"ts": 2.0, "pid": 100, "package": "com.example.app", "class": "android.app.Activity", "method": "onResume"},
        ]
        processor = make_processor(tmp_path, log_lines=events_in)
        result = processor.run()
        assert result["status"] == "captured"
        assert result["events"] == events_in

    def test_skips_malformed_lines(self, tmp_path):
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        with open(logs_dir / "frida.log", "w") as f:
            f.write("not json\n")
            f.write(json.dumps({"ts": 1.0, "method": "onResume"}) + "\n")

        processor = AndroidFrida()
        processor.set_path(str(tmp_path))
        result = processor.run()

        assert result["status"] == "captured"
        assert len(result["events"]) == 1
        assert result["events"][0]["method"] == "onResume"

    def test_key_name(self, tmp_path):
        processor = make_processor(tmp_path)
        processor.run()
        assert processor.key == "android_frida"
