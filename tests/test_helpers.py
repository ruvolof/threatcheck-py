from threatcheck.helpers import hex_dump


def test_empty_data_returns_empty_string():
  assert hex_dump(b'', 0) == ''


def test_single_byte_row_padded_to_16_cells():
  out = hex_dump(b'A', 1)
  # file_offset = 1 - 1 = 0
  assert out.startswith('00000000   ')
  # First hex cell is 41 (ASCII 'A'), remaining 15 cells are '  '
  assert '41 ' in out
  # ASCII column shows 'A' followed by 15 spaces
  assert out.endswith('A' + ' ' * 15)


def test_exactly_16_bytes_produces_single_line():
  data = bytes(range(16))
  out = hex_dump(data, 16)
  assert out.count('\n') == 0
  assert out.startswith('00000000   ')
  assert '00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F' in out


def test_17_bytes_produces_two_lines_with_incremented_offset():
  data = bytes(range(17))
  out = hex_dump(data, 17)
  lines = out.split('\n')
  assert len(lines) == 2
  # end_offset=17, len=17, file_offset = 0. Second row starts at 0x10.
  assert lines[0].startswith('00000000   ')
  assert lines[1].startswith('00000010   ')


def test_non_printable_bytes_shown_as_dot():
  out = hex_dump(b'\x00\x7fABC', 5)
  # Non-printable bytes (< 32 or > 126) render as '.'
  assert out.endswith('..ABC' + ' ' * 11)


def test_offset_zero_forces_printed_offset_to_zero():
  # When end_offset == 0, the printed offset stays at 0 regardless of position.
  data = bytes(range(32))
  out = hex_dump(data, 0)
  lines = out.split('\n')
  assert lines[0].startswith('00000000   ')
  assert lines[1].startswith('00000000   ')


def test_returned_value_is_str():
  assert isinstance(hex_dump(b'hi', 2), str)
