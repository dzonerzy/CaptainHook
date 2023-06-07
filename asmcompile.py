import sys
import argparse
import struct
import subprocess
import os


class BinaryReader:
    def __init__(self, array):
        self.backup = array
        self.array = array

    def read(self, size, unpack=False):
        data, self.array = self.array[:size], self.array[size:]
        if len(data) != size:
            raise Exception("End of file")
        if len(data) == 0:
            raise Exception("No data")
        if unpack:
            if len(data) == 2:
                return struct.unpack("<H", data)[0]
            if len(data) == 4:
                return struct.unpack("<I", data)[0]
            if len(data) == 8:
                return struct.unpack("<Q", data)[0]
        else:
            return data

    def bytes(self):
        return self.backup


class MachineType:
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_I386 = 0x14c

    def __init__(self, machine_type):
        self.machine_type = machine_type

    def __str__(self):
        if self.machine_type == self.IMAGE_FILE_MACHINE_AMD64:
            return "x86_64"
        elif self.machine_type == self.IMAGE_FILE_MACHINE_I386:
            return "x86"
        else:
            return "Unknown machine type"


class COFF_FileHeader:
    def __init__(self, binary: BinaryReader):
        self.machine = binary.read(2, True)
        self.num_sections = binary.read(2, True)
        self.time_date_stamp = binary.read(4, True)
        self.pointer_to_symbol_table = binary.read(4, True)
        self.num_symbols = binary.read(4, True)
        self.size_of_optional_header = binary.read(2, True)
        self.characteristics = binary.read(2, True)

    def __str__(self):
        return "Machine: " + str(MachineType(self.machine)) + "\n" + \
            "Number of Sections: " + str(self.num_sections) + "\n" + \
            "Time Date Stamp: " + str(self.time_date_stamp) + "\n" + \
            "Pointer to Symbol Table: " + str(self.pointer_to_symbol_table) + "\n" + \
            "Number of Symbols: " + str(self.num_symbols) + "\n" + \
            "Size of Optional Header: " + str(self.size_of_optional_header) + "\n" + \
            "Characteristics: " + str(self.characteristics) + "\n"


class COFF_SectionHeader:
    def __init__(self, binary: BinaryReader):
        self.name = binary.read(8).decode("utf-8").rstrip('\0')
        self.virtual_size = binary.read(4, True)
        self.virtual_address = binary.read(4, True)
        self.size_of_raw_data = binary.read(4, True)
        self.pointer_to_raw_data = binary.read(4, True)
        self.pointer_to_relocations = binary.read(4, True)

    def __str__(self):
        return "Name: " + self.name + "\n" + \
            "Virtual Size: " + str(self.virtual_size) + "\n" + \
            "Virtual Address: " + str(self.virtual_address) + "\n" + \
            "Size of Raw Data: " + str(self.size_of_raw_data) + "\n" + \
            "Pointer to Raw Data: " + str(self.pointer_to_raw_data) + "\n" + \
            "Pointer to Relocations: " + \
            str(self.pointer_to_relocations) + "\n"


class COFFParser:
    def __init__(self, binary: BinaryReader):
        self.binary = binary
        self.file_header = COFF_FileHeader(self.binary)
        self.section_headers = []
        for i in range(self.file_header.num_sections):
            self.section_headers.append(COFF_SectionHeader(self.binary))

    def _get_text_section(self):
        for section in self.section_headers:
            if section.name == ".text":
                return section
        return None

    def dump(self):
        text = self._get_text_section()
        if text is None:
            raise Exception("No text section found")
        data = self.binary.bytes()
        return data[text.pointer_to_raw_data:text.pointer_to_raw_data + text.size_of_raw_data]

    def __str__(self):
        return str(self.file_header) + "\n" + "\n".join(str(section) for section in self.section_headers)


def main():
    parser = argparse.ArgumentParser(description='Compile assembly code.')
    action = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('-input', help='input file')
    parser.add_argument('-nasm', type=str, help='path to nasm')
    action.add_argument('-x86', action='store_true',
                        help='x86 output file', required=False)
    action.add_argument('-x86_64',  action='store_true',
                        help='x86_64 output file', required=False)
    args = parser.parse_args()

    if args.x86:
        print("[+] Compiling x86")

    if args.x86_64:
        print("[+] Compiling x86_64")

    print("[+] Input file: " + args.input)
    print("[+] Nasm path: " + args.nasm)

    # check if nasm actually exists
    # check if input file exists

    proc = subprocess.Popen(
        [args.nasm, "-f", "win64" if args.x86_64 else "win32", args.input, '-O', '0', '-o', 'cpthook_stub.bin'], stdout=subprocess.PIPE)
    proc.wait()

    return_code = proc.returncode
    if return_code != 0:
        print("[-] Error compiling assembly code")
        sys.exit(1)

    binary = None

    with open('cpthook_stub.bin', 'rb') as f:
        binary = f.read()
        f.close()

    if binary is None:
        print("[-] Error reading compiled assembly code")
        sys.exit(1)

    coff = COFFParser(BinaryReader(binary))

    dump = coff.dump()
    # print to hex dump
    print("[+] Dumping compiled assembly code")

    with open("cpthook_stub.c", "wb") as f:
        f.write("\n// Generated by asmcompile.py, DO NOT EDIT\n\n".encode("utf-8"))
        f.write("unsigned long stub_size = {0};\n".format(
            len(dump)).encode("utf-8"))
        f.write("unsigned char stub[] = {\n".encode("utf-8"))
        for i in range(len(dump)):
            f.write("0x{:02x}".format(dump[i]).encode("utf-8"))
            if i != len(dump) - 1:
                f.write(", ".encode("utf-8"))
            if i % 16 == 15:
                f.write("\n".encode("utf-8"))
        f.write("};\n".encode("utf-8"))
        f.close()

    os.remove("cpthook_stub.bin")


if __name__ == "__main__":
    main()
