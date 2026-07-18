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
  # Indicates wether the scanner prints to stdout on its own. Ideally, scanners
  # should not print to stdout and instead return a ScanResult object, but some
  # scanners (like Yara) have their own logging and printing mechanisms.
  self_reports = False

  def __init__(self, file_bytes=None, debug=False, pid=None):
    if not file_bytes and not pid:
      raise ValueError('file_bytes or pid must be provided')
    if file_bytes and pid:
      raise ValueError('file_bytes and pid cannot be provided together')

    self.file_bytes = file_bytes
    self.debug = debug
    self.temp_dir = None
    self.pid = pid

  def analyze(self):
    """Starts data analysis on either process memory or file bytes."""
    self.temp_dir = tempfile.mkdtemp()
    try:
      if self.file_bytes:
        return self._start_file_scan()
      elif self.pid:
        return self._start_process_scan()
    finally:
      self._cleanup_temp_files()
  
  def _cleanup_temp_files(self):
    """Removes temporary files created during analysis."""
    for file in Path(self.temp_dir).iterdir():
      try:
        os.remove(file)
      except:
        Console.write_error(f'Failed to remove temporary file: {file}')
    
    try:
      os.rmdir(self.temp_dir)
    except:
      Console.write_error(
          f'Failed to remove temporary directory: {self.temp_dir}')
  
  @abstractmethod
  def _start_file_scan(self):
    """Subclasses implement their own logic to scan files"""
    pass

  @abstractmethod
  def _start_process_scan(self):
    """Subclasses implement their own logic to scan process memory"""
    pass
  
