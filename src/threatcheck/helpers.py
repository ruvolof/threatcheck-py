def hex_dump(data, end_offset):
  file_offset = end_offset - len(data)
  offset = 0

  while offset < len(data):
    print_offset = file_offset + offset if end_offset != 0 else 0
    
    line = f'{print_offset:08X}   '
    
    hex_part = []
    for i in range(16):
      if offset + i < len(data):
        hex_part.append(f'{data[offset + i]:02X}')
      else:
        hex_part.append('  ')
      
      if i == 7:
        hex_part.append('')
    
    line += ' '.join(hex_part)
    line += '  '
    
    ascii_part = ''
    for i in range(16):
      if offset + i < len(data):
        byte = data[offset + i]
        if 32 <= byte <= 126:
          ascii_part += chr(byte)
        else:
          ascii_part += '.'
      else:
        ascii_part += ' '
    
    line += ascii_part
    print(line)
    
    offset += 16
