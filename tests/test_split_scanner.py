import pytest

from threatcheck.scanners.scanner import ScanResult, ScanStatus
from threatcheck.scanners.split_scanner import SplitScanner


class _ThresholdSplitScanner(SplitScanner):
  """Detects a threat when the input has more than `threshold` bytes.

  Simulates a signature that is fully present iff the tail of the file is
  reached: any prefix of length > threshold is flagged. Lets us assert the
  binary-split algorithm converges to end_offset == threshold + 1.
  """

  SIGNATURE = 'FAKE_SIG'

  def __init__(self, threshold):
    super().__init__(debug=False)
    self.threshold = threshold
    self.scan_count = 0

  def _scan_bytes(self, data, get_sig=False):
    self.scan_count += 1
    r = ScanResult()
    if len(data) > self.threshold:
      r.status = ScanStatus.THREAT_FOUND
      if get_sig:
        r.signature = self.SIGNATURE
    else:
      r.status = ScanStatus.NO_THREAT_FOUND
    return r


def _make_file(size):
  # Deterministic byte pattern so offending_bytes assertions are precise.
  return bytes(i & 0xFF for i in range(size))


class TestCleanFile:
  def test_never_triggers_returns_no_threat(self):
    file_bytes = _make_file(1000)
    scanner = _ThresholdSplitScanner(threshold=10**9)
    result = scanner.analyze(file_bytes=file_bytes)
    assert result.status == ScanStatus.NO_THREAT_FOUND
    assert result.identified is False
    assert result.end_offset is None
    assert result.signature is None


class TestConvergence:
  # The binary-split loop's exit condition (len(orig) == split_size + 1)
  # combined with split_size = (N - last_good)//2 + last_good only fires when
  # N - last_good is 1 or 2. Since last_good caps at `threshold`, end_offset
  # lands in {threshold+1, threshold+2} — never further off. This is the
  # real correctness contract of the algorithm.
  @pytest.mark.parametrize('file_size, threshold', [
      (200, 100),
      (500, 42),
      (1024, 300),
      (10000, 4567),
      (10, 1),
  ])
  def test_converges_to_within_two_bytes_of_threshold(
      self, file_size, threshold):
    file_bytes = _make_file(file_size)
    scanner = _ThresholdSplitScanner(threshold=threshold)
    result = scanner.analyze(file_bytes=file_bytes)

    assert result.status == ScanStatus.THREAT_FOUND
    assert result.identified is True
    assert result.end_offset in (threshold + 1, threshold + 2)
    expected_len = min(result.end_offset, 256)
    assert len(result.offending_bytes) == expected_len
    assert result.offending_bytes == file_bytes[
        result.end_offset - expected_len:result.end_offset]

  def test_signature_captured_from_initial_scan(self):
    file_bytes = _make_file(500)
    scanner = _ThresholdSplitScanner(threshold=100)
    result = scanner.analyze(file_bytes=file_bytes)
    assert result.signature == _ThresholdSplitScanner.SIGNATURE

  def test_offending_bytes_capped_at_256(self):
    file_bytes = _make_file(4000)
    scanner = _ThresholdSplitScanner(threshold=1000)
    result = scanner.analyze(file_bytes=file_bytes)
    assert result.end_offset in (1001, 1002)
    assert len(result.offending_bytes) == 256
    assert result.offending_bytes == file_bytes[
        result.end_offset - 256:result.end_offset]

  def test_scan_count_is_logarithmic_not_linear(self):
    file_bytes = _make_file(100_000)
    scanner = _ThresholdSplitScanner(threshold=50_000)
    scanner.analyze(file_bytes=file_bytes)
    assert scanner.scan_count < 200

  def test_scanner_reused_across_files(self):
    scanner = _ThresholdSplitScanner(threshold=100)
    first = scanner.analyze(file_bytes=_make_file(500))
    second = scanner.analyze(file_bytes=_make_file(50))
    assert first.status == ScanStatus.THREAT_FOUND
    assert second.status == ScanStatus.NO_THREAT_FOUND


class TestBoundaryBehavior:
  def test_threat_at_end_of_file_exits_without_identification(self):
    # When the signature only triggers on the full file, the _overshot path
    # terminates the loop without populating end_offset.
    file_bytes = _make_file(200)
    scanner = _ThresholdSplitScanner(threshold=199)
    result = scanner.analyze(file_bytes=file_bytes)
    assert result.status == ScanStatus.THREAT_FOUND
    assert result.signature == _ThresholdSplitScanner.SIGNATURE
    assert result.identified is False
    assert result.end_offset is None

  def test_algorithm_terminates_on_tiny_file(self):
    file_bytes = _make_file(2)
    scanner = _ThresholdSplitScanner(threshold=0)
    result = scanner.analyze(file_bytes=file_bytes)
    assert result.status == ScanStatus.THREAT_FOUND
    assert result.identified is True
    assert result.end_offset == 1
    assert result.offending_bytes == file_bytes[:1]


class TestProcessScan:
  def test_process_scan_raises_not_implemented(self):
    scanner = _ThresholdSplitScanner(threshold=0)
    with pytest.raises(NotImplementedError,
                       match='Process scanning not implemented'):
      scanner.analyze(pid=42)
