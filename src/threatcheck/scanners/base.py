import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from enum import Enum

from threatcheck.console import Console
from threatcheck.helpers import hex_dump

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

class Scanner(ABC):
  def __init__(self, file_bytes=None, debug=False):
    if not file_bytes:
      raise ValueError('file_bytes must be provided')
    
    self.file_bytes = file_bytes
    self.debug = debug
    self.malicious = False
    self.complete = False
    self.temp_dir = None

  def analyze(self):
    """Starts data analysis on either process memory or file bytes."""
    self.temp_dir = tempfile.mkdtemp()
    try:
      self._start_file_scan()
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

  def _half_splitter(self, original_array, last_good):
    """Splits the array in half, keeping the first half.
    Called when a threat is found to reduce the data size."""
    split_size = (len(original_array) - last_good) // 2 + last_good
    split_array = original_array[:split_size]

    if len(original_array) == split_size + 1:
      msg = f'Identified end of bad bytes at offset 0x{len(original_array):X}'
      Console.write_threat(msg)

      offending_size = min(len(original_array), 256)
      offending_bytes = original_array[-offending_size:]

      hex_dump(offending_bytes, len(original_array))
      self.complete = True

    return split_array

  def _overshot(self, original_array, split_array_size):
    """Called when no threat is found to increase the data size."""
    new_size = (len(original_array) - split_array_size) // 2 + split_array_size

    if new_size == len(original_array) - 1:
      self.complete = True

      if self.malicious:
        Console.write_error('File is malicious, but couldn\'t identify bad bytes')

    return original_array[:new_size]
  
  def _binary_split_loop(self):
    """Common binary splitting logic.
    
    Searches the exact bytes where the signature ends by keeping track of the
    last known good bytes and splitting the remaining bytes in half.
    """  
    if self.debug:
      Console.write_debug(
          f'Size: {len(self.file_bytes)} bytes. Searching for signature.')
    
    split_array = self.file_bytes[:len(self.file_bytes) // 2]
    last_good = 0
    
    while not self.complete:
      if self.debug:
        Console.write_debug(f'Testing {len(split_array)} bytes')
      
      detection_result = self._scan_bytes(split_array)
      
      if detection_result.status == ScanStatus.THREAT_FOUND:
        if self.debug:
          Console.write_debug('Threat found, splitting')
        
        split_array = self._half_splitter(split_array, last_good)
      else:
        if self.debug:
          Console.write_debug('No threat found, increasing size')
        
        last_good = len(split_array)
        split_array = self._overshot(self.file_bytes, len(split_array))
  
  def _start_file_scan(self):
    """Analyze file bytes with binary splitting"""
    initial_status = self._scan_bytes(self.file_bytes, get_sig=True)
    
    if initial_status.status == ScanStatus.THREAT_FOUND:
      self.malicious = True
      Console.write_threat(f'File is malicious.')
      if initial_status.signature:
        Console.write_threat(f'Signature: {initial_status.signature}')
      self._binary_split_loop()
    else:
      Console.write_output('No threat found!')
  
  @abstractmethod
  def _scan_bytes(self, data, get_sig=False):
    """Subclasses implement specific scan methods.
    
    Args:
        data: The bytes to scan
        
    Returns:
        bool: True if threat detected, False otherwise
    """
    pass
