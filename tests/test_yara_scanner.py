import pytest

from threatcheck.scanners.scanner import ScanStatus
from threatcheck.scanners.yara_scanner import YaraScanner


MARKER = b'MALICIOUS_MARKER_XYZ'

GOOD_RULE = """\
rule Detect_Marker {
    strings:
        $m = "MALICIOUS_MARKER_XYZ"
    condition:
        $m
}
"""

NESTED_RULE = """\
rule Detect_Nested {
    strings:
        $n = "NESTED_MARKER_ABC"
    condition:
        $n
}
"""

BAD_RULE = """\
rule Broken {
    condition:
        this is not valid yara syntax
"""


@pytest.fixture
def rules_dir(tmp_path):
  """Rules directory containing a valid rule, an invalid rule to be skipped,
  and a nested subdirectory with another valid rule."""
  (tmp_path / 'good.yar').write_text(GOOD_RULE)
  (tmp_path / 'bad.yar').write_text(BAD_RULE)
  nested = tmp_path / 'sub'
  nested.mkdir()
  (nested / 'nested.yara').write_text(NESTED_RULE)
  # Non-yara files should be ignored.
  (tmp_path / 'readme.txt').write_text('not a rule')
  return tmp_path


class TestCompileRules:
  def test_valid_rules_compile_and_bad_files_skipped(self, rules_dir):
    scanner = YaraScanner(file_bytes=b'x', rules_path=str(rules_dir))
    assert scanner.compiled_rules is not None

  def test_empty_directory_raises(self, tmp_path):
    with pytest.raises(RuntimeError, match='No valid YARA rules found'):
      YaraScanner(file_bytes=b'x', rules_path=str(tmp_path))

  def test_directory_with_only_invalid_rules_raises(self, tmp_path):
    (tmp_path / 'bad.yar').write_text(BAD_RULE)
    with pytest.raises(RuntimeError, match='No valid YARA rules found'):
      YaraScanner(file_bytes=b'x', rules_path=str(tmp_path))

  def test_rules_path_required(self):
    with pytest.raises(ValueError, match='rules_path must be provided'):
      YaraScanner(file_bytes=b'x')


class TestStartFileScan:
  def test_matching_input_returns_threat_found(self, rules_dir, capsys):
    payload = b'benign junk ' + MARKER + b' trailing bytes'
    scanner = YaraScanner(file_bytes=payload, rules_path=str(rules_dir))
    result = scanner._start_file_scan()
    assert result.status == ScanStatus.THREAT_FOUND
    # YaraScanner self-reports; drain the captured output so it doesn't leak.
    capsys.readouterr()

  def test_non_matching_input_returns_no_threat(self, rules_dir, capsys):
    scanner = YaraScanner(file_bytes=b'plain harmless content',
                          rules_path=str(rules_dir))
    result = scanner._start_file_scan()
    assert result.status == ScanStatus.NO_THREAT_FOUND
    capsys.readouterr()

  def test_nested_rule_directory_is_walked(self, rules_dir, capsys):
    scanner = YaraScanner(file_bytes=b'NESTED_MARKER_ABC in payload',
                          rules_path=str(rules_dir))
    result = scanner._start_file_scan()
    assert result.status == ScanStatus.THREAT_FOUND
    capsys.readouterr()
