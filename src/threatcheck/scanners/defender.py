import os
import sys
import subprocess
from pathlib import Path
from enum import Enum

from threatcheck.scanners.scanner import ScanResult, ScanStatus
from threatcheck.scanners.split_scanner import SplitScanner
from threatcheck.console import Console


def _parse_defender_signature(stdout):
  """Parse MpCmdRun.exe stdout and return the signature name, or None.

  Example output from Defender:
    <===========================LIST OF DETECTED THREATS==========================>
    ----------------------------- Threat information ------------------------------
    Threat                  : Trojan:Win64/Meterpreter!pz
    Resources               : 1 total
        file                : C:\\Temp\\File.exe
  """
  for line in stdout.split('\n'):
    if line.startswith('Threat'):
      parts = line.split(':', maxsplit=1)
      if len(parts) == 2:
        return parts[1].strip()
      return None
  return None


class DefenderScanner(SplitScanner):
  def __init__(self, file_bytes=None, debug=False, pid=None):
    super().__init__(file_bytes=file_bytes, debug=debug, pid=pid)

    if self.pid:
      raise ValueError(
          'Defender scanner does not support scanning process memory')
    
    if sys.platform != 'win32':
      raise RuntimeError(
          'Platform not supported: Defender scanner requires Windows')
    
    self.mpcmdrun_path = Path(r'C:\Program Files\Windows Defender\MpCmdRun.exe')
    if not self.mpcmdrun_path.exists():
      raise FileNotFoundError(
          f'MpCmdRun.exe not found at {self.mpcmdrun_path}')
  
  def _scan_bytes(self, data, get_sig=False) -> ScanResult:
    """Scan a data split for threats"""
    # Defender needs to scan from disk, not memory.
    testfile_path = os.path.join(self.temp_dir, 'file.exe')
    with open(testfile_path, 'wb') as f:
      f.write(data)
    
    return self._scan_file(testfile_path, get_sig=get_sig)

  def _scan_file(self, file_path, get_sig=False) -> ScanResult:
    result = ScanResult()
    
    if not os.path.exists(file_path):
      result.status = ScanStatus.FILE_NOT_FOUND
      return result
    
    try:
      cmd = [
        str(self.mpcmdrun_path),
        '-Scan',
        '-ScanType', '3',
        '-File', file_path,
        '-DisableRemediation',
        '-Trace',
        '-Level', '0x10'
      ]
      
      process = subprocess.Popen(
          cmd,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE,
          creationflags=subprocess.CREATE_NO_WINDOW)
      
      try:
        stdout, stderr = process.communicate(timeout=30)
      except subprocess.TimeoutExpired:
        process.kill()
        result.status = ScanStatus.TIMEOUT
        return result
      
      if process.returncode == 0:
        result.status = ScanStatus.NO_THREAT_FOUND
      elif process.returncode == 2:
        result.status = ScanStatus.THREAT_FOUND
        if get_sig:
          result.signature = _parse_defender_signature(
              stdout.decode('utf-8', errors='ignore'))
      else:
        result.status = ScanStatus.ERROR
      
      return result
    
    except Exception as e:
      Console.write_error(f'Error scanning file: {e}')
      result.status = ScanStatus.ERROR
      return result

