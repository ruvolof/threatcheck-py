import sys

import pytest

from threatcheck.scanners.amsi import AmsiScanner


class TestAmsiScannerInit:
  def test_pid_rejected_on_any_os(self):
    with pytest.raises(ValueError, match='does not support scanning process'):
      AmsiScanner(pid=1)

  @pytest.mark.skipif(sys.platform == 'win32',
                      reason='Non-Windows platform check only')
  def test_non_windows_raises_runtime_error(self):
    with pytest.raises(RuntimeError, match='requires Windows'):
      AmsiScanner(file_bytes=b'x')
