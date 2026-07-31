import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from threatcheck import cli
from threatcheck.scanners.scanner import ScanResult, ScanStatus
from threatcheck.scanners.yara_scanner import YaraMatch, YaraStringMatch


class _StubScanner:
  def __init__(self, results=None, raise_exc=None):
    self._results = list(results) if results else []
    self._raise_exc = raise_exc
    self.calls = []

  def analyze(self, file_bytes=None, pid=None):
    self.calls.append({'file_bytes': file_bytes, 'pid': pid})
    if self._raise_exc:
      raise self._raise_exc
    if self._results:
      return self._results.pop(0)
    r = ScanResult()
    r.status = ScanStatus.NO_THREAT_FOUND
    return r


class TestDownloadFileBytes:
  def test_returns_content_on_success(self):
    with patch.object(cli.requests, 'get') as get:
      response = MagicMock()
      response.content = b'downloaded bytes'
      get.return_value = response
      assert cli.download_file_bytes('http://x/file') == b'downloaded bytes'
      get.assert_called_once_with('http://x/file', timeout=30)
      response.raise_for_status.assert_called_once()

  def test_request_exception_wrapped_as_runtime_error(self):
    with patch.object(cli.requests, 'get',
                      side_effect=requests.ConnectionError('boom')):
      with pytest.raises(RuntimeError, match='Could not connect to URL'):
        cli.download_file_bytes('http://x/file')


class TestListFilesInDirectory:
  def test_returns_files_only(self, tmp_path):
    (tmp_path / 'a.bin').write_bytes(b'')
    (tmp_path / 'b.bin').write_bytes(b'')
    (tmp_path / 'subdir').mkdir()
    result = cli.list_files_in_directory(tmp_path)
    assert {p.name for p in result} == {'a.bin', 'b.bin'}

  def test_missing_directory_exits(self, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
      cli.list_files_in_directory(tmp_path / 'nonexistent')
    assert excinfo.value.code == 1

  def test_path_is_not_a_directory_exits(self, tmp_path):
    f = tmp_path / 'notadir'
    f.write_bytes(b'')
    with pytest.raises(SystemExit) as excinfo:
      cli.list_files_in_directory(f)
    assert excinfo.value.code == 1

  def test_empty_directory_exits(self, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
      cli.list_files_in_directory(tmp_path)
    assert excinfo.value.code == 1


class TestReadFileContent:
  def test_reads_bytes(self, tmp_path):
    f = tmp_path / 'sample.bin'
    payload = bytes(range(256))
    f.write_bytes(payload)
    assert cli.read_file_content(f) == payload


class TestReportResult:
  def test_threat_found_with_identified_bytes_dumps_hex(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.THREAT_FOUND
    r.signature = 'Trojan.Test'
    r.identified = True
    r.end_offset = 5
    r.offending_bytes = b'ABCDE'
    cli.report_result(r)
    out = capsys.readouterr().out
    assert 'malicious' in out
    assert 'Trojan.Test' in out
    assert '0x5' in out
    assert '41 42 43 44 45' in out

  def test_threat_found_without_identification_reports_error(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.THREAT_FOUND
    r.identified = False
    cli.report_result(r)
    captured = capsys.readouterr()
    assert 'malicious' in captured.out
    assert "couldn't identify bad bytes" in captured.err

  def test_no_threat_found_prints_ok(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.NO_THREAT_FOUND
    cli.report_result(r)
    assert 'No threat found' in capsys.readouterr().out

  def test_error_status_produces_no_report_output(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.ERROR
    cli.report_result(r)
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == ''

  def test_yara_matches_render_rule_identifier_offset_and_hex(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.THREAT_FOUND
    r.matches = [
        YaraMatch(rule='Detect_X', strings=[
            YaraStringMatch(identifier='$a', offset=0x10, matched_data=b'BAD'),
        ]),
    ]
    cli.report_result(r)
    out = capsys.readouterr().out
    assert 'malicious' in out
    assert 'YARA matches found: 1' in out
    assert 'Rule: Detect_X' in out
    assert '$a Offset: 0x10' in out
    assert '\\x42\\x41\\x44' in out

  def test_yara_matches_render_multi_rule_and_multi_instance(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.THREAT_FOUND
    r.matches = [
        YaraMatch(rule='RuleA', strings=[
            YaraStringMatch(identifier='$a', offset=0x10, matched_data=b'X'),
            YaraStringMatch(identifier='$a', offset=0x40, matched_data=b'X'),
        ]),
        YaraMatch(rule='RuleB', strings=[
            YaraStringMatch(identifier='$b', offset=0x80, matched_data=b'Y'),
        ]),
    ]
    cli.report_result(r)
    out = capsys.readouterr().out
    assert 'YARA matches found: 2' in out
    assert 'Rule: RuleA' in out and 'Rule: RuleB' in out
    assert '0x10' in out and '0x40' in out and '0x80' in out

  def test_yara_match_without_identifier_omits_prefix(self, capsys):
    r = ScanResult()
    r.status = ScanStatus.THREAT_FOUND
    r.matches = [
        YaraMatch(rule='R', strings=[
            YaraStringMatch(identifier='', offset=0x20, matched_data=b'x'),
        ]),
    ]
    cli.report_result(r)
    out = capsys.readouterr().out
    assert 'Offset: 0x20 Match: b"\\x78"' in out
    assert '\t' not in out


class TestPrintSummary:
  def _mk(self, status, path='f'):
    r = ScanResult()
    r.status = status
    r.file_path = path
    return r

  def test_summary_no_threats(self, capsys):
    cli.print_summary([
        self._mk(ScanStatus.NO_THREAT_FOUND, 'a'),
        self._mk(ScanStatus.NO_THREAT_FOUND, 'b'),
    ])
    out = capsys.readouterr().out
    assert '2 successful, 0 errors' in out
    assert 'No threats found' in out

  def test_summary_with_threats_lists_paths(self, capsys):
    cli.print_summary([
        self._mk(ScanStatus.THREAT_FOUND, 'evil.exe'),
        self._mk(ScanStatus.NO_THREAT_FOUND, 'clean.txt'),
        self._mk(ScanStatus.ERROR, 'broken.bin'),
    ])
    out = capsys.readouterr().out
    assert '2 successful, 1 errors' in out
    assert 'Found 1 threats' in out
    assert 'evil.exe' in out


class TestParseArguments:
  def test_defaults(self, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['threatcheck', '-f', 'sample.bin'])
    args = cli.parse_arguments()
    assert args.engine == 'defender'
    assert args.file == 'sample.bin'
    assert args.url is None
    assert args.directory is None
    assert args.pid is None
    assert args.rules is None
    assert args.debug is False

  def test_engine_normalized_to_lowercase(self, monkeypatch):
    monkeypatch.setattr(
        sys, 'argv', ['threatcheck', '--engine', 'YARA', '-f', 'sample.bin'])
    args = cli.parse_arguments()
    assert args.engine == 'yara'

  def test_invalid_engine_exits(self, monkeypatch):
    monkeypatch.setattr(
        sys, 'argv',
        ['threatcheck', '--engine', 'bogus', '-f', 'sample.bin'])
    with pytest.raises(SystemExit):
      cli.parse_arguments()

  def test_debug_flag(self, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['threatcheck', '--debug', '-f', 's.bin'])
    args = cli.parse_arguments()
    assert args.debug is True

  def test_version_exits(self, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['threatcheck', '--version'])
    with pytest.raises(SystemExit) as excinfo:
      cli.parse_arguments()
    assert excinfo.value.code == 0

  def test_no_source_flag_exits(self, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['threatcheck'])
    with pytest.raises(SystemExit) as excinfo:
      cli.parse_arguments()
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert 'one of the arguments' in err
    for flag in ('-f/--file', '-u/--url', '-d/--directory', '-p/--pid'):
      assert flag in err

  def test_source_flags_are_mutually_exclusive(self, monkeypatch, capsys):
    monkeypatch.setattr(
        sys, 'argv', ['threatcheck', '-f', 'a.bin', '-d', '/tmp'])
    with pytest.raises(SystemExit) as excinfo:
      cli.parse_arguments()
    assert excinfo.value.code == 2
    assert 'not allowed with argument' in capsys.readouterr().err

  def test_pid_parsed_as_int(self, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['threatcheck', '-p', '4242'])
    args = cli.parse_arguments()
    assert args.pid == 4242
    assert isinstance(args.pid, int)

  def test_pid_non_integer_exits_with_argparse_error(
      self, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['threatcheck', '-p', 'notanumber'])
    with pytest.raises(SystemExit) as excinfo:
      cli.parse_arguments()
    assert excinfo.value.code == 2
    assert 'invalid int value' in capsys.readouterr().err

  def test_rules_with_yara_engine_is_accepted(self, monkeypatch):
    monkeypatch.setattr(
        sys, 'argv',
        ['threatcheck', '-e', 'yara', '-r', '/tmp/rules', '-f', 's.bin'])
    args = cli.parse_arguments()
    assert args.rules == '/tmp/rules'

  def test_rules_with_non_yara_engine_is_rejected(self, monkeypatch, capsys):
    monkeypatch.setattr(
        sys, 'argv',
        ['threatcheck', '-e', 'defender', '-r', '/tmp/rules', '-f', 's.bin'])
    with pytest.raises(SystemExit) as excinfo:
      cli.parse_arguments()
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert '--rules is only valid with --engine yara' in err
    assert 'defender' in err


class TestInitializeScanner:
  def test_unknown_engine_raises_value_error(self):
    with pytest.raises(ValueError, match='Unknown engine: bogus'):
      cli.initialize_scanner('bogus', debug=False)

  def test_yara_engine_builds_scanner(self, tmp_path):
    (tmp_path / 'r.yar').write_text(
        'rule R { strings: $a = "x" condition: $a }')
    scanner = cli.initialize_scanner(
        'yara', debug=False, rules_path=str(tmp_path))
    from threatcheck.scanners.yara_scanner import YaraScanner
    assert isinstance(scanner, YaraScanner)


class TestProcessFiles:
  def test_scanner_instance_is_reused_across_files(self, tmp_path):
    (tmp_path / 'a.bin').write_bytes(b'aaa')
    (tmp_path / 'b.bin').write_bytes(b'bb')
    files = sorted(tmp_path.iterdir())
    scanner = _StubScanner()

    cli.process_files(scanner, files)

    assert len(scanner.calls) == 2
    assert scanner.calls[0]['file_bytes'] == b'aaa'
    assert scanner.calls[1]['file_bytes'] == b'bb'

  def test_scan_error_produces_error_result_without_stopping(self, tmp_path):
    (tmp_path / 'a.bin').write_bytes(b'x')
    (tmp_path / 'b.bin').write_bytes(b'y')
    files = sorted(tmp_path.iterdir())
    scanner = _StubScanner(raise_exc=RuntimeError('boom'))

    results = cli.process_files(scanner, files)

    assert len(results) == 2
    assert all(r.status == ScanStatus.ERROR for r in results)
    assert all(r.error_message == 'boom' for r in results)


class TestMainInitFailure:
  def test_scanner_init_failure_exits_without_scanning(
      self, monkeypatch, capsys, tmp_path):
    (tmp_path / 'a.bin').write_bytes(b'x')
    (tmp_path / 'b.bin').write_bytes(b'y')

    monkeypatch.setattr(
        sys, 'argv',
        ['threatcheck', '-e', 'amsi', '-d', str(tmp_path)])
    monkeypatch.setattr(
        cli, 'initialize_scanner',
        MagicMock(side_effect=RuntimeError('AMSI unavailable')))

    with pytest.raises(SystemExit) as excinfo:
      cli.main()

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert 'Failed to initialize amsi scanner' in err
    assert 'AMSI unavailable' in err
    # Init error printed once, not per file.
    assert err.count('AMSI unavailable') == 1

  def test_no_source_flag_exits_before_scanner_init(
      self, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['threatcheck'])
    init_mock = MagicMock()
    monkeypatch.setattr(cli, 'initialize_scanner', init_mock)

    with pytest.raises(SystemExit) as excinfo:
      cli.main()

    # argparse rejects the missing source flag before main() runs and exits 2.
    assert excinfo.value.code == 2
    assert init_mock.call_count == 0
    assert 'one of the arguments' in capsys.readouterr().err
