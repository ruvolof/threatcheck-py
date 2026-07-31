import pytest

from threatcheck.scanners import clamav
from threatcheck.scanners.clamav import ClamAVScanner, _parse_clamav_signature


class TestParseClamavSignature:
  def test_single_detection(self):
    stdout = '/tmp/file.exe: Win.Trojan.Agent-1234 FOUND\n'
    assert _parse_clamav_signature(stdout) == 'Win.Trojan.Agent-1234'

  def test_first_match_wins_when_multiple_present(self):
    stdout = (
        '/tmp/a: First.Sig FOUND\n'
        '/tmp/b: Second.Sig FOUND\n'
    )
    assert _parse_clamav_signature(stdout) == 'First.Sig'

  def test_no_match_returns_none(self):
    stdout = '----------- SCAN SUMMARY -----------\nInfected files: 0\n'
    assert _parse_clamav_signature(stdout) is None

  def test_empty_string_returns_none(self):
    assert _parse_clamav_signature('') is None

  def test_malformed_line_without_colon_is_skipped(self):
    stdout = 'malformed FOUND\n/tmp/x: Real.Sig FOUND\n'
    assert _parse_clamav_signature(stdout) == 'Real.Sig'

  def test_signature_with_colons_preserved(self):
    stdout = '/tmp/x: Category:Family/Variant FOUND\n'
    assert _parse_clamav_signature(stdout) == 'Category:Family/Variant'


class TestClamAVScannerInit:
  def test_missing_binaries_raises_runtime_error(self, monkeypatch):
    monkeypatch.setattr(clamav.shutil, 'which', lambda name: None)
    with pytest.raises(RuntimeError, match='ClamAV not found'):
      ClamAVScanner()

  def test_prefers_clamdscan_when_present(self, monkeypatch):
    def which(name):
      return f'/usr/bin/{name}' if name == 'clamdscan' else None
    monkeypatch.setattr(clamav.shutil, 'which', which)
    scanner = ClamAVScanner()
    assert scanner._uses_clamd is True
    assert scanner.clamscan_path == '/usr/bin/clamdscan'

  def test_falls_back_to_clamscan(self, monkeypatch):
    def which(name):
      return '/usr/bin/clamscan' if name == 'clamscan' else None
    monkeypatch.setattr(clamav.shutil, 'which', which)
    scanner = ClamAVScanner()
    assert scanner._uses_clamd is False
    assert scanner.clamscan_path == '/usr/bin/clamscan'

  def test_analyze_pid_raises_not_implemented(self, monkeypatch):
    def which(name):
      return f'/usr/bin/{name}' if name == 'clamdscan' else None
    monkeypatch.setattr(clamav.shutil, 'which', which)
    scanner = ClamAVScanner()
    with pytest.raises(NotImplementedError,
                       match='Process scanning not implemented'):
      scanner.analyze(pid=1)
