import sys

import pytest

from threatcheck.scanners.amsi import AmsiScanner


class TestAmsiScannerInit:
  @pytest.mark.skipif(sys.platform == 'win32',
                      reason='Non-Windows platform check only')
  def test_non_windows_raises_runtime_error(self):
    with pytest.raises(RuntimeError, match='requires Windows'):
      AmsiScanner()
