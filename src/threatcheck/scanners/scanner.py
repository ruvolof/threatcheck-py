import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from enum import Enum

from threatcheck.console import Console

class ScanStatus(Enum):
  NO_THREAT_FOUND = 0
  THREAT_FOUND = 1
  FILE_NOT_FOUND = 2
  TIMEOUT = 3
  ERROR = 4

class ScanResult:
  def __init__(self):
    self.status = None
    self.signature = None
    self.offending_bytes = None
    self.end_offset = None
    self.identified = False
    self.matches = None
    self.file_path = None
    self.file_size = None
    self.error_message = None

  @property
  def malicious(self):
    return self.status == ScanStatus.THREAT_FOUND

  @property
  def success(self):
    return self.status in (ScanStatus.NO_THREAT_FOUND, ScanStatus.THREAT_FOUND)

class Scanner(ABC):
  def __init__(self, debug=False):
    self.debug = debug
    self.temp_dir = None

  def analyze(self, file_bytes=None, pid=None):
    """Starts data analysis on either process memory or file bytes."""
    if file_bytes is None and pid is None:
      raise ValueError('file_bytes or pid must be provided')
    if file_bytes is not None and pid is not None:
      raise ValueError('file_bytes and pid cannot be provided together')

    self.temp_dir = tempfile.mkdtemp()
    try:
      if file_bytes is not None:
        return self._start_file_scan(file_bytes)
      return self._start_process_scan(pid)
    finally:
      self._cleanup_temp_files()

  def _cleanup_temp_files(self):
    """Removes temporary files created during analysis."""
    for file in Path(self.temp_dir).iterdir():
      try:
        os.remove(file)
      except OSError as e:
        Console.write_error(f'Failed to remove temporary file {file}: {e}')

    try:
      os.rmdir(self.temp_dir)
    except OSError as e:
      Console.write_error(
          f'Failed to remove temporary directory {self.temp_dir}: {e}')

  @abstractmethod
  def _start_file_scan(self, file_bytes):
    """Subclasses implement their own logic to scan files"""
    pass

  @abstractmethod
  def _start_process_scan(self, pid):
    """Subclasses implement their own logic to scan process memory"""
    pass

