import os

import pytest

from threatcheck.scanners.scanner import Scanner, ScanResult, ScanStatus


class _FakeScanner(Scanner):
  def __init__(self, raise_in_scan=False):
    super().__init__()
    self.raise_in_scan = raise_in_scan
    self.file_scan_called = False
    self.process_scan_called = False
    self.recorded_temp_dir = None
    self.recorded_file_bytes = None
    self.recorded_pid = None

  def _start_file_scan(self, file_bytes):
    self.file_scan_called = True
    self.recorded_temp_dir = self.temp_dir
    self.recorded_file_bytes = file_bytes
    if self.raise_in_scan:
      raise RuntimeError('scan failure')
    return ScanResult()

  def _start_process_scan(self, pid):
    self.process_scan_called = True
    self.recorded_temp_dir = self.temp_dir
    self.recorded_pid = pid
    return ScanResult()


class TestScanStatus:
  def test_all_expected_members_present(self):
    assert {s.name for s in ScanStatus} == {
        'NO_THREAT_FOUND',
        'THREAT_FOUND',
        'FILE_NOT_FOUND',
        'TIMEOUT',
        'ERROR',
    }


class TestScanResult:
  @pytest.mark.parametrize('status, malicious, success', [
      (ScanStatus.THREAT_FOUND, True, True),
      (ScanStatus.NO_THREAT_FOUND, False, True),
      (ScanStatus.FILE_NOT_FOUND, False, False),
      (ScanStatus.TIMEOUT, False, False),
      (ScanStatus.ERROR, False, False),
      (None, False, False),
  ])
  def test_properties(self, status, malicious, success):
    r = ScanResult()
    r.status = status
    assert r.malicious is malicious
    assert r.success is success

  def test_default_field_values(self):
    r = ScanResult()
    assert r.status is None
    assert r.signature is None
    assert r.offending_bytes is None
    assert r.end_offset is None
    assert r.identified is False
    assert r.file_path is None
    assert r.file_size is None
    assert r.error_message is None


class TestScannerAnalyze:
  def test_neither_file_bytes_nor_pid_raises(self):
    s = _FakeScanner()
    with pytest.raises(ValueError, match='file_bytes or pid must be provided'):
      s.analyze()

  def test_both_file_bytes_and_pid_raises(self):
    s = _FakeScanner()
    with pytest.raises(ValueError, match='cannot be provided together'):
      s.analyze(file_bytes=b'x', pid=1)

  def test_dispatches_to_file_scan(self):
    s = _FakeScanner()
    s.analyze(file_bytes=b'x')
    assert s.file_scan_called is True
    assert s.process_scan_called is False
    assert s.recorded_file_bytes == b'x'

  def test_dispatches_to_process_scan(self):
    s = _FakeScanner()
    s.analyze(pid=1)
    assert s.process_scan_called is True
    assert s.file_scan_called is False
    assert s.recorded_pid == 1

  def test_pid_zero_is_accepted(self):
    s = _FakeScanner()
    s.analyze(pid=0)
    assert s.process_scan_called is True
    assert s.recorded_pid == 0

  def test_scanner_can_be_reused_across_calls(self):
    s = _FakeScanner()
    s.analyze(file_bytes=b'a')
    first_temp = s.recorded_temp_dir
    s.analyze(file_bytes=b'b')
    second_temp = s.recorded_temp_dir
    assert first_temp != second_temp
    assert not os.path.exists(first_temp)
    assert not os.path.exists(second_temp)
    assert s.recorded_file_bytes == b'b'

  def test_creates_and_cleans_up_temp_dir(self):
    s = _FakeScanner()
    s.analyze(file_bytes=b'x')
    assert s.recorded_temp_dir is not None
    assert not os.path.exists(s.recorded_temp_dir)

  def test_cleans_up_temp_dir_even_if_scan_raises(self):
    s = _FakeScanner(raise_in_scan=True)
    with pytest.raises(RuntimeError, match='scan failure'):
      s.analyze(file_bytes=b'x')
    assert s.recorded_temp_dir is not None
    assert not os.path.exists(s.recorded_temp_dir)

  def test_cleanup_handles_leftover_files_in_temp_dir(self):
    class _LeavesFile(_FakeScanner):
      def _start_file_scan(self, file_bytes):
        self.recorded_temp_dir = self.temp_dir
        with open(os.path.join(self.temp_dir, 'trash'), 'wb') as f:
          f.write(b'garbage')
        return ScanResult()

    s = _LeavesFile()
    s.analyze(file_bytes=b'x')
    assert not os.path.exists(s.recorded_temp_dir)

  def test_keyboard_interrupt_from_scan_is_not_swallowed_by_cleanup(self):
    class _Interrupter(_FakeScanner):
      def _start_file_scan(self, file_bytes):
        self.recorded_temp_dir = self.temp_dir
        raise KeyboardInterrupt

    s = _Interrupter()
    with pytest.raises(KeyboardInterrupt):
      s.analyze(file_bytes=b'x')
    assert not os.path.exists(s.recorded_temp_dir)

  def test_cleanup_failure_reports_reason(self, monkeypatch, capsys):
    def deny(path):
      raise PermissionError('denied')

    s = _FakeScanner()
    monkeypatch.setattr(os, 'rmdir', deny)
    s.analyze(file_bytes=b'x')
    err = capsys.readouterr().err
    assert 'Failed to remove temporary directory' in err
    assert 'denied' in err
