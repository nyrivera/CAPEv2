import json
import unittest
from unittest.mock import MagicMock, mock_open, patch

from modules.auxiliary import frida


class FridaTestCase(unittest.TestCase):
    def setUp(self):
        frida.notify_target(None, None)

    def tearDown(self):
        frida.notify_target(None, None)

    def make_aux(self):
        return frida.Frida(options={}, analyzer=None)


class TestFridaStart(FridaTestCase):
    @patch("modules.auxiliary.frida.os.path.isfile", return_value=False)
    def test_start_disables_when_binary_missing(self, mock_isfile):
        aux = self.make_aux()
        aux.start()
        self.assertFalse(aux.available)

    @patch("modules.auxiliary.frida.os.path.isfile", return_value=True)
    @patch("modules.auxiliary.frida.os.access", return_value=False)
    def test_start_disables_when_binary_not_executable(self, mock_access, mock_isfile):
        aux = self.make_aux()
        aux.start()
        self.assertFalse(aux.available)

    @patch("modules.auxiliary.frida.os.path.isfile", return_value=True)
    @patch("modules.auxiliary.frida.os.access", return_value=True)
    def test_start_enables_when_present(self, mock_access, mock_isfile):
        aux = self.make_aux()
        aux.start()
        self.assertTrue(aux.available)


class TestFridaGetPids(FridaTestCase):
    def test_get_pids_noop_when_unavailable(self):
        aux = self.make_aux()
        aux.available = False
        frida.notify_target("com.example.app", 1234)
        self.assertEqual(aux.get_pids(), [])
        self.assertFalse(aux.injection_attempted)

    def test_get_pids_noop_when_no_target_yet(self):
        aux = self.make_aux()
        aux.available = True
        self.assertEqual(aux.get_pids(), [])
        self.assertFalse(aux.injection_attempted)

    @patch("modules.auxiliary.frida.subprocess.Popen")
    def test_get_pids_injects_once(self, mock_popen):
        aux = self.make_aux()
        aux.available = True
        frida.notify_target("com.example.app", 1234)

        aux.get_pids()
        aux.get_pids()
        aux.get_pids()

        mock_popen.assert_called_once()
        self.assertTrue(aux.injection_attempted)
        self.assertEqual(aux.injected_pid, 1234)

    @patch("modules.auxiliary.frida.subprocess.Popen", side_effect=OSError("no such file"))
    def test_get_pids_survives_popen_failure(self, mock_popen):
        aux = self.make_aux()
        aux.available = True
        frida.notify_target("com.example.app", 1234)

        # Must not raise -- a failed injection is not a failed analysis.
        self.assertEqual(aux.get_pids(), [])
        self.assertIsNone(aux.proc)


class TestFridaInjectArgv(FridaTestCase):
    @patch("modules.auxiliary.frida.subprocess.Popen")
    def test_inject_uses_positional_parameter_substitution(self, mock_popen):
        """package_name is attacker-controlled (it comes out of the
        submitted APK's manifest) -- the injected argv must never
        string-interpolate it into a shell command body, only pass it as a
        positional parameter, matching modules/packages/apk.py's _launch().
        This test targets pid/paths since those are what actually reach
        the shell body here; package_name itself never reaches the
        frida-inject argv at all.
        """
        aux = self.make_aux()
        aux.available = True
        aux._inject(1234, "com.example.app")

        argv = mock_popen.call_args[0][0]
        self.assertEqual(argv[0], "sh")
        self.assertEqual(argv[1], "-c")
        self.assertEqual(argv[3], "sh")
        self.assertNotIn("1234", argv[2])


class TestFridaStop(FridaTestCase):
    def test_stop_noop_when_never_injected(self):
        aux = self.make_aux()
        aux.proc = None
        aux.stop()  # must not raise

    @patch("modules.auxiliary.frida.Frida._upload_events")
    def test_stop_terminates_running_process(self, mock_upload):
        aux = self.make_aux()
        aux.proc = MagicMock()
        aux.proc.poll.return_value = None

        aux.stop()

        aux.proc.terminate.assert_called_once()
        mock_upload.assert_called_once()

    @patch("modules.auxiliary.frida.Frida._upload_events")
    def test_stop_skips_terminate_when_already_exited(self, mock_upload):
        aux = self.make_aux()
        aux.proc = MagicMock()
        aux.proc.poll.return_value = 0

        aux.stop()

        aux.proc.terminate.assert_not_called()
        mock_upload.assert_called_once()


class TestFridaUploadEvents(FridaTestCase):
    @patch("modules.auxiliary.frida.os.path.exists", return_value=False)
    def test_upload_noop_when_log_missing(self, mock_exists):
        aux = self.make_aux()
        aux._upload_events()  # must not raise, nothing to assert against I/O

    @patch("modules.auxiliary.frida.append_buffer_to_host")
    @patch("modules.auxiliary.frida.NetlogFile")
    @patch("modules.auxiliary.frida.os.path.exists", return_value=True)
    def test_upload_parses_and_tags_events(self, mock_exists, mock_netlogfile, mock_append):
        frida.notify_target("com.example.app", 1234)
        aux = self.make_aux()

        log_lines = (
            json.dumps({"type": "send", "payload": {"ts": 1.0, "pid": 1234, "class": None, "method": None, "hook_status": "ok"}})
            + "\n"
            + "not json at all\n"
            + json.dumps({"type": "log", "payload": "ignored, not a send frame"})
            + "\n"
            + json.dumps({"type": "send", "payload": {"ts": 2.0, "pid": 1234, "class": "android.app.Activity", "method": "onResume"}})
            + "\n"
        )

        with patch("builtins.open", mock_open(read_data=log_lines)):
            aux._upload_events()

        uploaded_lines = [call.args[0].decode() for call in mock_append.call_args_list]
        self.assertEqual(len(uploaded_lines), 2)
        first = json.loads(uploaded_lines[0])
        second = json.loads(uploaded_lines[1])
        self.assertEqual(first["package"], "com.example.app")
        self.assertEqual(second["method"], "onResume")
        self.assertEqual(second["package"], "com.example.app")

    @patch("modules.auxiliary.frida.append_buffer_to_host")
    @patch("modules.auxiliary.frida.NetlogFile")
    @patch("modules.auxiliary.frida.os.path.exists", return_value=True)
    def test_upload_noop_when_no_send_frames(self, mock_exists, mock_netlogfile, mock_append):
        aux = self.make_aux()
        with patch("builtins.open", mock_open(read_data=json.dumps({"type": "log", "payload": "x"}) + "\n")):
            aux._upload_events()
        mock_append.assert_not_called()
