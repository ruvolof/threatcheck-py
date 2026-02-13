import os
import subprocess
import shutil

from threatcheck.scanners.base import Scanner, ScanResult, ScanStatus
from threatcheck.console import Console


class ClamAVScanner(Scanner):
  def __init__(self, file_bytes=None, debug=False):
    super().__init__(file_bytes=file_bytes, debug=debug)

    self._uses_clamd = False
    
    # Check if clamscan is available
    if shutil.which('clamdscan'):
      self.clamscan_path = shutil.which('clamdscan')
      self._uses_clamd = True
    else:
      self.clamscan_path = shutil.which('clamscan')
    if not self.clamscan_path:
      raise RuntimeError(
          'ClamAV not found. Ensure clamdscan or clamscan are in your PATH')
    if not self._uses_clamd:
      Console.write_debug(
          'Using clamscan. Install clamav-daemon for better performance')
  
  def _scan_bytes(self, data, get_sig=False) -> ScanResult:
    """Scan a data split for threats"""
    # ClamAV needs to scan from disk, not memory.
    testfile_path = os.path.join(self.temp_dir, 'testfile')
    with open(testfile_path, 'wb') as f:
      f.write(data)
    if self._uses_clamd:
      # clamav-daemon runs as clamav, making test file readable by all
      os.chmod(self.temp_dir, 0o755)
      os.chmod(testfile_path, 0o755)
    
    return self._scan_file(testfile_path, get_sig=get_sig)

  def _scan_file(self, file_path, get_sig=False) -> ScanResult:
    result = ScanResult()
    
    if not os.path.exists(file_path):
      result.status = ScanStatus.FILE_NOT_FOUND
      return result
    
    try:
      cmd = [
        self.clamscan_path,
        '--no-summary',
        '--infected',
        file_path
      ]
      
      process = subprocess.Popen(
          cmd,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE
      )
      
      try:
        stdout, stderr = process.communicate(timeout=30)
      except subprocess.TimeoutExpired:
        process.kill()
        result.status = ScanStatus.TIMEOUT
        return result

      # ClamAV exit codes:
      # 0 = No virus found
      # 1 = Virus found
      if process.returncode == 0:
        result.status = ScanStatus.NO_THREAT_FOUND
      elif process.returncode == 1:
        result.status = ScanStatus.THREAT_FOUND
        if get_sig:
          output = stdout.decode('utf-8', errors='ignore')
          # ClamAV output format: {file_path}: {signature_name} FOUND
          # Example: /tmp/file.exe: Win.Trojan.Agent-1234 FOUND
          for line in output.split('\n'):
            if ' FOUND' in line:
              # Extract signature between ': ' and ' FOUND'
              parts = line.split(': ')
              if len(parts) >= 2:
                sig_part = parts[1]
                if ' FOUND' in sig_part:
                  result.signature = sig_part.replace(' FOUND', '').strip()
                  break
      else:
        result.status = ScanStatus.ERROR
      
      return result
    
    except Exception as e:
      Console.write_error(f'Error scanning file: {e}')
      result.status = ScanStatus.ERROR
      return result

