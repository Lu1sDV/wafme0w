"""Real subprocess regressions for the usage matrix's deadline and cleanup contracts."""
import os
from pathlib import Path
import signal
import selectors
import sys
import tempfile
import unittest

if not sys.platform.startswith("linux"):
    raise unittest.SkipTest("Linux subprocess and kernel-pipe regressions")

import httpx_usage_matrix as matrix


class MatrixProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="httpx-matrix-test-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.matrix = matrix.Matrix(Path(sys.executable), [], root)
        self.addCleanup(self.matrix.server.server_close)
        self.case = matrix.Case(self.matrix, "process")

    def test_readable_output_cannot_renew_expired_deadline(self):
        command = [sys.executable, "-c", "import os,signal;os.write(1,b'ready\\n');signal.pause()"]
        with self.case.child(command, pipe=True, timeout=0) as child:
            with selectors.DefaultSelector() as selector:
                selector.register(child.process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(3), "fixture did not make stdout readable")
            # Readability cannot turn an expired absolute deadline into a new wait.
            with self.assertRaises(TimeoutError):
                child.first_line()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_exited_leader_does_not_leave_descendant_running(self):
        pid_file = self.case.path / "descendant.pid"
        command = [sys.executable, "-c", "\n".join([
            "import os,signal,sys",
            "from pathlib import Path",
            "reader,writer=os.pipe()",
            "pid=os.fork()",
            "if pid==0:",
            " os.close(reader)",
            " Path(sys.argv[1]).write_text(str(os.getpid()))",
            " os.write(writer,b'R');os.close(writer)",
            " signal.pause()",
            "else:",
            " os.close(writer);os.read(reader,1);os.close(reader)",
        ]), str(pid_file)]
        descendant = None
        try:
            with self.case.child(command) as child:
                child.finish()
                descendant = int(pid_file.read_text())
            def stopped():
                try:
                    # A zombie has stopped too; the OS reaper owns its final entry.
                    return Path(f"/proc/{descendant}/stat").read_text().split(")", 1)[1].split()[0] == "Z"
                except FileNotFoundError:
                    return True
            try:
                matrix.wait_until(stopped, "descendant survived its exited leader", timeout=1)
            except TimeoutError:
                self.fail("process-group cleanup skipped after the immediate child exited")
        finally:
            if descendant is not None:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
