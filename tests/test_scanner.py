import os

import pytest

from threatcheck.scanners.scanner import Scanner, ScanResult, ScanStatus


class _FakeScanner(Scanner):
  def __init__(self, file_bytes=None, pid=None, raise_in_scan=False):
    super().__init__(file_bytes=file_bytes, pid=pid)
    self.raise_in_scan = raise_in_scan
    self.file_scan_called = False
    self.process_scan_called = False
    self.recorded_temp_dir = None

  def _start_file_scan(self):
    self.file_scan_called = True
    self.recorded_temp_dir = self.temp_dir
    if self.raise_in_scan:
      raise RuntimeError('scan failure')
    return ScanResult()

  def _start_process_scan(self):
    self.process_scan_called = True
    self.recorded_temp_dir = self.temp_dir
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


class TestScannerInit:
  def test_neither_file_bytes_nor_pid_raises(self):
    with pytest.raises(ValueError, match='file_bytes or pid must be provided'):
      _FakeScanner()

  def test_both_file_bytes_and_pid_raises(self):
    with pytest.raises(ValueError, match='cannot be provided together'):
      _FakeScanner(file_bytes=b'x', pid=1)

  def test_file_bytes_only_ok(self):
    s = _FakeScanner(file_bytes=b'x')
    assert s.file_bytes == b'x'
    assert s.pid is None

  def test_pid_only_ok(self):
    s = _FakeScanner(pid=42)
    assert s.pid == 42
    assert s.file_bytes is None


class TestScannerAnalyze:
  def test_dispatches_to_file_scan(self):
    s = _FakeScanner(file_bytes=b'x')
    s.analyze()
    assert s.file_scan_called is True
    assert s.process_scan_called is False

  def test_dispatches_to_process_scan(self):
    s = _FakeScanner(pid=1)
    s.analyze()
    assert s.process_scan_called is True
    assert s.file_scan_called is False

  def test_creates_and_cleans_up_temp_dir(self):
    s = _FakeScanner(file_bytes=b'x')
    s.analyze()
    assert s.recorded_temp_dir is not None
    assert not os.path.exists(s.recorded_temp_dir)

  def test_cleans_up_temp_dir_even_if_scan_raises(self):
    s = _FakeScanner(file_bytes=b'x', raise_in_scan=True)
    with pytest.raises(RuntimeError, match='scan failure'):
      s.analyze()
    assert s.recorded_temp_dir is not None
    assert not os.path.exists(s.recorded_temp_dir)

  def test_cleanup_handles_leftover_files_in_temp_dir(self):
    class _LeavesFile(_FakeScanner):
      def _start_file_scan(self):
        self.recorded_temp_dir = self.temp_dir
        with open(os.path.join(self.temp_dir, 'trash'), 'wb') as f:
          f.write(b'garbage')
        return ScanResult()

    s = _LeavesFile(file_bytes=b'x')
    s.analyze()
    assert not os.path.exists(s.recorded_temp_dir)
