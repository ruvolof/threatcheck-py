from abc import ABC, abstractmethod

from threatcheck.scanners.scanner import Scanner, ScanStatus, ScanResult
from threatcheck.console import Console


class SplitScanner(Scanner):
  def _start_file_scan(self, file_bytes):
    """Analyze file bytes with binary splitting"""
    result = ScanResult()
    view = memoryview(file_bytes)
    initial_result = self._scan_bytes(view, get_sig=True)

    if initial_result.status != ScanStatus.THREAT_FOUND:
      result.status = ScanStatus.NO_THREAT_FOUND
      return result

    result.status = ScanStatus.THREAT_FOUND
    result.signature = initial_result.signature
    self._binary_split_loop(view, result)
    return result

  def _start_process_scan(self, pid):
    """Analyze process memory with binary splitting"""
    raise NotImplementedError(
        'Process scanning not implemented for split scanners')

  @abstractmethod
  def _scan_bytes(self, data, get_sig=False):
    """Subclasses implement specific scan methods.

    Args:
        data: The bytes to scan
        get_sig: When True, populate `signature` on the returned result

    Returns:
        ScanResult: with at least `status` set, and `signature` when
        `get_sig=True` and a threat was detected.
    """
    pass

  def _half_splitter(self, original_array, last_good, result):
    """Splits the array in half, keeping the first half.
    Called when a threat is found to reduce the data size.

    Returns (split_array, complete)."""
    split_size = (len(original_array) - last_good) // 2 + last_good
    split_array = original_array[:split_size]
    complete = False

    if len(original_array) == split_size + 1:
      offending_size = min(len(original_array), 256)
      result.end_offset = len(original_array)
      result.offending_bytes = bytes(original_array[-offending_size:])
      result.identified = True
      complete = True

    return split_array, complete

  def _overshot(self, original_array, split_array_size):
    """Called when no threat is found to increase the data size.

    Returns (new_array, complete)."""
    new_size = (len(original_array) - split_array_size) // 2 + split_array_size
    complete = new_size == len(original_array) - 1
    return original_array[:new_size], complete

  def _binary_split_loop(self, file_bytes, result):
    """Common binary splitting logic.

    Searches the exact bytes where the signature ends by keeping track of the
    last known good bytes and splitting the remaining bytes in half.
    """
    if self.debug:
      Console.write_debug(
          f'Size: {len(file_bytes)} bytes. Searching for signature.')

    split_array = file_bytes[:len(file_bytes) // 2]
    last_good = 0
    complete = False

    while not complete:
      if self.debug:
        Console.write_debug(f'Testing {len(split_array)} bytes')

      detection_result = self._scan_bytes(split_array)

      if detection_result.status == ScanStatus.THREAT_FOUND:
        if self.debug:
          Console.write_debug('Threat found, splitting')

        split_array, complete = self._half_splitter(
            split_array, last_good, result)
      else:
        if self.debug:
          Console.write_debug('No threat found, increasing size')

        last_good = len(split_array)
        split_array, complete = self._overshot(
            file_bytes, len(split_array))
