import pytest

from threatcheck.scanners.scanner import ScanStatus
from threatcheck.scanners.yara_scanner import (
    YaraScanner, YaraMatch, YaraStringMatch)


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
  (tmp_path / 'readme.txt').write_text('not a rule')
  return tmp_path


class TestCompileRules:
  def test_valid_rules_compile_and_bad_files_skipped(self, rules_dir):
    scanner = YaraScanner(rules_path=str(rules_dir))
    assert scanner.compiled_rules is not None

  def test_empty_directory_raises(self, tmp_path):
    with pytest.raises(RuntimeError, match='No valid YARA rules found'):
      YaraScanner(rules_path=str(tmp_path))

  def test_directory_with_only_invalid_rules_raises(self, tmp_path):
    (tmp_path / 'bad.yar').write_text(BAD_RULE)
    with pytest.raises(RuntimeError, match='No valid YARA rules found'):
      YaraScanner(rules_path=str(tmp_path))

  def test_rules_path_required(self):
    with pytest.raises(ValueError, match='rules_path must be provided'):
      YaraScanner()


class TestStartFileScan:
  def test_matching_input_returns_threat_found_with_populated_matches(
      self, rules_dir, capsys):
    payload = b'benign junk ' + MARKER + b' trailing bytes'
    scanner = YaraScanner(rules_path=str(rules_dir))
    capsys.readouterr()
    result = scanner.analyze(file_bytes=payload)

    assert result.status == ScanStatus.THREAT_FOUND
    assert result.matches is not None and len(result.matches) == 1
    match = result.matches[0]
    assert isinstance(match, YaraMatch)
    assert match.rule == 'Detect_Marker'
    assert len(match.strings) == 1
    string = match.strings[0]
    assert isinstance(string, YaraStringMatch)
    assert string.identifier == '$m'
    assert string.matched_data == MARKER
    assert string.offset == payload.index(MARKER)

    captured = capsys.readouterr()
    assert captured.out == '' and captured.err == ''

  def test_non_matching_input_returns_no_threat_with_matches_none(
      self, rules_dir, capsys):
    scanner = YaraScanner(rules_path=str(rules_dir))
    capsys.readouterr()
    result = scanner.analyze(file_bytes=b'plain harmless content')

    assert result.status == ScanStatus.NO_THREAT_FOUND
    assert result.matches is None
    captured = capsys.readouterr()
    assert captured.out == '' and captured.err == ''

  def test_nested_rule_directory_is_walked(self, rules_dir):
    scanner = YaraScanner(rules_path=str(rules_dir))
    result = scanner.analyze(file_bytes=b'NESTED_MARKER_ABC in payload')
    assert result.status == ScanStatus.THREAT_FOUND
    assert [m.rule for m in result.matches] == ['Detect_Nested']

  def test_multiple_rules_matching_produce_multiple_match_entries(
      self, rules_dir):
    payload = MARKER + b' and NESTED_MARKER_ABC together'
    scanner = YaraScanner(rules_path=str(rules_dir))
    result = scanner.analyze(file_bytes=payload)

    assert result.status == ScanStatus.THREAT_FOUND
    rules_matched = {m.rule for m in result.matches}
    assert rules_matched == {'Detect_Marker', 'Detect_Nested'}

  def test_scanner_reused_across_scans(self, rules_dir):
    scanner = YaraScanner(rules_path=str(rules_dir))
    first = scanner.analyze(file_bytes=MARKER)
    second = scanner.analyze(file_bytes=b'harmless')
    assert first.status == ScanStatus.THREAT_FOUND
    assert second.status == ScanStatus.NO_THREAT_FOUND
