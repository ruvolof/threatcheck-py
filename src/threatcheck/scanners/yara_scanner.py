import os
import re
import sys
import yara
import ctypes
from typing import Dict

from threatcheck.scanners.scanner import Scanner, ScanResult, ScanStatus
from threatcheck.console import Console


class YaraStringMatch:
  def __init__(self, identifier, offset, matched_data):
    self.identifier = identifier
    self.offset = offset
    self.matched_data = matched_data


class YaraMatch:
  def __init__(self, rule, strings):
    self.rule = rule
    self.strings = strings


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

  def _build_result(self, matches):
    result = ScanResult()
    if not matches:
      result.status = ScanStatus.NO_THREAT_FOUND
      return result

    result.status = ScanStatus.THREAT_FOUND
    result.matches = []
    for match in matches:
      strings = []
      for string_match in match.strings:
        for instance in string_match.instances:
          strings.append(YaraStringMatch(
              identifier=string_match.identifier,
              offset=instance.offset,
              matched_data=instance.matched_data))
      result.matches.append(YaraMatch(rule=match.rule, strings=strings))

    return result

  def _start_file_scan(self):
    matches = self.compiled_rules.match(data=self.file_bytes)
    return self._build_result(matches)

  def _start_process_scan(self):
    matches = self.compiled_rules.match(pid=int(self.pid))
    return self._build_result(matches)
