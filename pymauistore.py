import struct
import os
import lz4.block
from elftools.elf.elffile import ELFFile

ASSEMBLY_STORE_MAGIC = 0x41424158
COMPRESSED_DATA_MAGIC = b"XALZ"


class AssemblyStoreHeader:
    def __init__(self, magic, version, entry_count, index_entry_count, index_size):
        self.magic = magic
        self.version = version
        self.entry_count = entry_count
        self.index_entry_count = index_entry_count
        self.index_size = index_size

    @staticmethod
    def from_file(f):
        data = f.read(20)
        magic, version, entry_count, index_entry_count, index_size = struct.unpack('<5I', data)
        if magic != ASSEMBLY_STORE_MAGIC:
            raise ValueError("Invalid magic number, not an assembly store file")
        return AssemblyStoreHeader(magic, version, entry_count, index_entry_count, index_size)


class AssemblyStoreEntryDescriptor:
    def __init__(self, mapping_index, data_offset, data_size, debug_offset, debug_size,
                 config_offset, config_size):
        self.mapping_index = mapping_index
        self.data_offset = data_offset
        self.data_size = data_size
        self.debug_offset = debug_offset
        self.debug_size = debug_size
        self.config_offset = config_offset
        self.config_size = config_size

    @staticmethod
    def from_file(f):
        data = f.read(7 * 4)
        return AssemblyStoreEntryDescriptor(*struct.unpack('<7I', data))


class AssemblyStore:
    def __init__(self, file_path):
        self.file_path = file_path
        self.header = None
        self.descriptors = []
        self.names = []

    def load(self):
        with open(self.file_path, 'rb') as f:
            self.header = AssemblyStoreHeader.from_file(f)
            f.seek(self.header.index_size, os.SEEK_CUR)
            for _ in range(self.header.entry_count):
                self.descriptors.append(AssemblyStoreEntryDescriptor.from_file(f))
            for _ in range(self.header.entry_count):
                name_length = struct.unpack('<I', f.read(4))[0]
                name = f.read(name_length).decode('utf-8')
                self.names.append(name)

    @staticmethod
    def decompress_lz4(compressed_data):
        packed_payload_len = compressed_data[8:12]
        unpacked_payload_len = struct.unpack('<I', packed_payload_len)[0]
        compressed_payload = compressed_data[12:]
        return lz4.block.decompress(compressed_payload, uncompressed_size=unpacked_payload_len)

    def extract_assemblies(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        with open(self.file_path, 'rb') as f:
            for desc, name in zip(self.descriptors, self.names):
                f.seek(desc.data_offset)
                assembly_data = f.read(desc.data_size)
                if assembly_data.startswith(COMPRESSED_DATA_MAGIC):
                    print(f"Decompressing {name}")
                    try:
                        assembly_data = self.decompress_lz4(assembly_data)
                    except (lz4.block.LZ4BlockError, struct.error, ValueError) as e:
                        print(f"Warning: Failed to decompress {name}: {e}, skipping.")
                        continue
                if not name.endswith(".dll"):
                    name += ".dll"
                out_path = os.path.join(output_dir, name)
                dir_path = os.path.dirname(out_path)
                os.makedirs(dir_path, exist_ok=True)
                with open(out_path, 'wb') as out_file:
                    out_file.write(assembly_data)
                print(f"Extracted: {out_path}")


def extract_payload_from_so(input_so, payload_path):
    with open(input_so, 'rb') as so_file:
        elf = ELFFile(so_file)
        section = elf.get_section_by_name('payload')
        if not section:
            raise ValueError("Payload section not found in provided .so file.")
        with open(payload_path, 'wb') as payload_file:
            payload_file.write(section.data())


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python3 pymauistore.py <libassemblies.arm64-v8a.blob.so> <output_dir>")
        sys.exit(1)

    input_so = sys.argv[1]
    output_directory = sys.argv[2]
    payload_path = 'payload.bin'

    extract_payload_from_so(input_so, payload_path)

    store = AssemblyStore(payload_path)
    store.load()
    store.extract_assemblies(output_directory)

    os.remove(payload_path)
