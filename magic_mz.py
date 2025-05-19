import subprocess
import random
import os

# Create more NOP-equivalent instruction pairs
x86_pairs = [
    ("dec ebp", "inc ebp"),
    ("push edx", "pop edx"),
    ("push eax", "pop eax"),
    
]

# Create more NOP-equivalent instruction pairs
x64_pairs = [
    ("push rdx", "pop rdx"),
    ("pop r9", "push r9"),
    ("push rcx", "pop rcx"),
]

def random_x86_sequence():
    pairs = random.sample(x86_pairs, 2)
    return [instr for pair in pairs for instr in pair]

def random_x64_sequence():
    return list(random.choice(x64_pairs))

def write_asm_file(filename, instructions, bits=32):
    with open(filename, "w") as f:
        f.write(f"bits {bits}\nsection .text\nglobal _start\n_start:\n")
        for instr in instructions:
            f.write(f"    {instr}\n")

def compile_asm(filename, output_bin):
    subprocess.run(["nasm", "-f", "bin", "-o", output_bin, filename], check=True)

def get_ascii_bytes(binfile):
    with open(binfile, "rb") as f:
        data = f.read(4)  # First 4 bytes
    ascii_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    return ascii_chars

def cleanup_temp(files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("Copy the following options to your Cobalt Strike profile.\n")
    
    # === X86 ===
    x86_instrs = random_x86_sequence()
    write_asm_file("x86-origin.asm", x86_instrs, bits=32)
    compile_asm("x86-origin.asm", "x86-origin.bin")
    x86_ascii = get_ascii_bytes("x86-origin.bin")
    #print(f"[x86] Instructions: {x86_instrs}")
    print(f"set magic_mz_x86 \"{x86_ascii}\";")

    # === X64 ===
    x64_instrs = random_x64_sequence()
    write_asm_file("x64-origin.asm", x64_instrs, bits=64)
    compile_asm("x64-origin.asm", "x64-origin.bin")
    x64_ascii = get_ascii_bytes("x64-origin.bin")
    #print(f"[x64] Instructions: {x64_instrs}")
    print(f"set magic_mz_x64 \"{x64_ascii}\";")

    cleanup_temp(["x86-origin.bin", "x64-origin.bin", "x64-origin.asm", "x86-origin.asm"])

if __name__ == "__main__":
    main()

