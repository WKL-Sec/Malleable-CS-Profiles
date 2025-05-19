import pefile
import sys
import os
import datetime

def format_time(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).strftime('%d %b %Y %H:%M:%S')

def get_rich_header(pe):
    try:
        # Parse the Rich Header using pefile
        rich_header = pe.parse_rich_header()

        if rich_header is None:
            return "Rich Header not found"
        
        # Extract raw data from the Rich Header
        raw_data = rich_header['raw_data']

        # Return the raw data as a hex string in \xXX format
        return '\\x' + '\\x'.join(f'{b:02x}' for b in raw_data)
    except Exception as e:
        return f"Error parsing Rich Header: {e}"

def get_dll_info(dll_path):
    """Parse the DLL and extract metadata."""
    try:
        # Load the PE file
        pe = pefile.PE(dll_path)

        # Extract various pieces of information
        checksum = pe.OPTIONAL_HEADER.CheckSum
        compile_time = format_time(pe.FILE_HEADER.TimeDateStamp)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        dll_name = os.path.basename(dll_path)
        
        # Retrieve Rich Header info
        rich_header = get_rich_header(pe)

        # Printing the information in the Cobalt Strike format
        print(f"set name \"{dll_name}\";")
        print(f"set checksum \"{checksum}\";")
        print(f"set compile_time \"{compile_time}\";")
        print(f"set entry_point \"{entry_point}\";")
        print(f"set image_size_x64 \"{int(pe.OPTIONAL_HEADER.SizeOfImage)}\";")
        print(f"set image_size_x86 \"{int(pe.OPTIONAL_HEADER.SizeOfImage)}\";")
        print(f"set rich_header \"{rich_header}\";")

    except FileNotFoundError:
        print("Error: DLL file not found.")
    except pefile.PEFormatError:
        print("Error: Invalid PE file.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dll_parse.py <path_to_dll>")
        sys.exit(1)

    # Path to the DLL or EXE file
    dll_path = sys.argv[1]
    get_dll_info(dll_path)
