import sys
from ctypes import c_void_p
from unittest.mock import MagicMock

import pytest

from threatcheck.scanners.amsi import AmsiResult, AmsiScanner


class TestAmsiScannerInit:
  @pytest.mark.skipif(sys.platform == 'win32',
                      reason='Non-Windows platform check only')
  def test_non_windows_raises_runtime_error(self):
    with pytest.raises(RuntimeError, match='requires Windows'):
      AmsiScanner()


class TestScanBuffer:
  def _stub_scanner(self, ret_code, result_value=0):
    scanner = AmsiScanner.__new__(AmsiScanner)
    scanner.amsi = MagicMock()
    scanner.amsi_context = c_void_p()
    scanner.amsi_session = c_void_p()

    def fake_scan_buffer(ctx, buf, size, name, session, result_ptr):
      result_ptr._obj.value = result_value
      return ret_code

    scanner.amsi.AmsiScanBuffer.side_effect = fake_scan_buffer
    return scanner

  def test_non_zero_return_raises_runtime_error(self):
    scanner = self._stub_scanner(ret_code=0x80070005)
    with pytest.raises(RuntimeError, match='AmsiScanBuffer failed with code'):
      scanner._scan_buffer(b'payload')

  def test_success_returns_amsi_result(self):
    scanner = self._stub_scanner(
        ret_code=0, result_value=int(AmsiResult.AMSI_RESULT_DETECTED))
    assert scanner._scan_buffer(b'payload') == AmsiResult.AMSI_RESULT_DETECTED
