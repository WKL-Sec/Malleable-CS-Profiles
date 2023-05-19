import sys

def replace_bytes(input_filename, output_filename):
    search_bytes      = b"\x25\xff\xff\xff\x00\x3d\x41\x41\x41\x00"
    replacement_bytes = b"\xb8\x41\x41\x41\x00\x3D\x41\x41\x41\x00"
  
    with open(input_filename, "rb") as input_file:
        content = input_file.read()
        modified_content = content.replace(search_bytes, replacement_bytes)
    
    with open(output_filename, "wb") as output_file:
        output_file.write(modified_content)
    
    print(f"Replacement complete. Modified content saved to {output_filename}.")

if len(sys.argv) == 2:
    input_filename = sys.argv[1]
    output_filename = "output.bin"
    replace_bytes(input_filename, output_filename)
else:
    print("No arguments provided")

#find
#25 FF FF FF 00 3D 41 41 41 00
#and eax,0xffffff
#cmp eax,0x414141

#replace to
#b8 41 41 41 00 3d 41 41 41 00
#mov eax,0x414141
#cmp eax,0x414141 

