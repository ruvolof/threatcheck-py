import sys

import pytest

from threatcheck.scanners.defender import (
    DefenderScanner,
    _parse_defender_signature,
)


DEFENDER_SAMPLE_OUTPUT = """\
<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Trojan:Win64/Meterpreter!pz
Resources               : 1 total
    file                : C:\\Temp\\File.exe
"""


class TestParseDefenderSignature:
  def test_extracts_signature_from_sample_output(self):
    assert _parse_defender_signature(
        DEFENDER_SAMPLE_OUTPUT) == 'Trojan:Win64/Meterpreter!pz'

  def test_no_threat_line_returns_none(self):
    stdout = 'Scan complete, no threats.\n'
    assert _parse_defender_signature(stdout) is None

  def test_empty_string_returns_none(self):
    assert _parse_defender_signature('') is None

  def test_signature_with_colons_preserved(self):
    stdout = 'Threat : Category:Family/Variant!marker\n'
    assert _parse_defender_signature(stdout) == 'Category:Family/Variant!marker'

  def test_only_first_threat_line_returned(self):
    stdout = (
        'Threat : First.Sig\n'
        'Threat : Second.Sig\n'
    )
    assert _parse_defender_signature(stdout) == 'First.Sig'


class TestDefenderScannerInit:
  @pytest.mark.skipif(sys.platform == 'win32',
                      reason='Non-Windows platform check only')
  def test_non_windows_raises_runtime_error(self):
    with pytest.raises(RuntimeError, match='requires Windows'):
      DefenderScanner()
