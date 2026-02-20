import os
import re
import sys
import yara
import ctypes
from typing import Dict

from threatcheck.scanners.scanner import Scanner, ScanResult, ScanStatus
from threatcheck.console import Console


class YaraScanner(Scanner):
  def __init__(self, file_bytes=None, debug=False, pid=None, rules_path=None):
    super().__init__(file_bytes=file_bytes, debug=debug, pid=pid)

    if not rules_path:
      raise ValueError('rules_path must be provided for YaraScanner')

    self.rules_path = rules_path
    self.compiled_rules = None
    self.compiled_rules_count = 0
    self._compile_rules()

  def _compile_rules(self):
    """Crawl the rules directory, fix duplicate identifiers, skip bad files,
    and compile all valid rules into a single `yara.Rules` object.
    """
    sources: Dict[str, str] = {}
    rule_name_count = {}

    file_index = 0
    for root, _, files in os.walk(self.rules_path):
      for fname in files:
        if not fname.lower().endswith(('.yar', '.yara')):
          continue

        path = os.path.join(root, fname)
        try:
          with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
        except Exception as e:
          Console.write_error(f'Failed to read YARA file {path}: {e}')
          continue

        # Quick compile test for this source to skip invalid rules early
        try:
          yara.compile(source=src)
        except yara.SyntaxError as e:
          Console.write_error(f'Skipping invalid YARA file {path}: {e}')
          continue
        except Exception as e:
          Console.write_error(f'Unexpected error compiling {path}: {e}')
          continue

        ns = f'ns{file_index}'
        sources[ns] = src
        file_index += 1

    if not sources:
      raise RuntimeError('No valid YARA rules found in provided path')

    if self.debug:
      Console.write_debug(f'Compiling {len(sources)} yara sources...')

    try:
      # Compile all sources at once
      self.compiled_rules = yara.compile(sources=sources)
    except Exception as e:
      raise RuntimeError(f'Failed to compile combined yara rules: {e}')

  def _report_matches(self, matches):
    """Format and output yara matches."""
    result = ScanResult()
    if not matches:
      result.status = ScanStatus.NO_THREAT_FOUND
      Console.write_output('No threat found!')
      return result

    result.status = ScanStatus.THREAT_FOUND
    self.malicious = True
    Console.write_threat(f'YARA matches found: {len(matches)}')
    for match in matches:
      print('\n')
      Console.write_threat(f'Rule: {match.rule}')
      for string_match in match.strings:
        identifier = getattr(string_match, 'identifier', None)
        # sm.instances is a list of StringMatchInstance
        instances = getattr(string_match, 'instances', [])
        for instance in instances:
          # extract offset and matched bytes
          offset = getattr(instance, 'offset', None)
          data = instance.matched_data
          hex_esc = ''.join(f'\\x{c:02x}' for c in data)
          if identifier:
            Console.write_threat(f'\t{identifier} Offset: 0x{offset:X} Match: b"{hex_esc}" -> {data}')
          else:
            Console.write_threat(f'Offset: 0x{offset:X} Match: b"{hex_esc}"')

    return result

  def _start_file_scan(self):
    # Use yara to match bytes directly
    try:
      matches = self.compiled_rules.match(data=self.file_bytes)
      res = self._report_matches(matches)
      return res
    except Exception as e:
      Console.write_error(f'YARA file scan failed: {e}')
      r = ScanResult()
      r.status = ScanStatus.ERROR
      return r

  def _start_process_scan(self):
    try:
      matches = self.compiled_rules.match(pid=int(self.pid))
      return self._report_matches(matches)
    except yara.Error as e:
      Console.write_error(f'YARA process scan failed: {e}')
      r = ScanResult()
      r.status = ScanStatus.ERROR
      return r
    except Exception as e:
      Console.write_error(f'Unexpected error scanning process: {e}')
      r = ScanResult()
      r.status = ScanStatus.ERROR
      return r
