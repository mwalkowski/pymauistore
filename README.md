# .NET MAUI 9 AssemblyStore Extractor
This script extracts and decompresses .NET DLL assemblies embedded within `.so` ELF files (`libassemblies.<arch>.blob.so`) generated by .NET MAUI 9 for Android applications.

## Introduction
With .NET MAUI 9 (formerly Xamarin), DLL libraries are no longer stored separately but embedded within ELF shared library files (`.so`), specifically named `libassemblies.<arch>.blob.so`. This makes extracting and analyzing .NET assemblies slightly more complex than in previous versions.
This Python script automates the extraction of embedded DLL files from such ELF files, facilitating further analysis and reverse engineering of Android applications developed with .NET MAUI 9.

## Requirements
- Python 3
- `pyelftools`
- `lz4`

You can install dependencies using pip:

```bash
pip install -r requrements.txt
```

## Usage
To extract the embedded DLLs from a `.so` file:
```bash
python unpack_assemblies.py libassemblies.arm64-v8a.blob.so output_dir
```

- Replace `libassemblies.arm64-v8a.blob.so` with your target `.so` file path.
- Replace `output_dir` with your desired extraction directory.

The script will:
- Extract the payload from the ELF `.so` file.
- Parse the payload and decompress assemblies if needed.
- Save DLL files to the specified output directory.

## Example Directory Structure After Extraction
```
output_dir/
├── System.IO.dll
├── System.Net.dll
├── Xamarin.Forms.dll
└── ...dll
```

## Details
- **`libassemblies.arm64-v8a.blob.so`**: Contains embedded .NET DLLs.
- **Payload extraction**: Uses the ELF format (pyelftools) to locate the hidden payload.
- DLL libraries might be LZ4-compressed (`XALZ` header). This script automatically decompresses them.

## Credits
- Michał Walkowski ([Original article](https://michalwalkowski.com))


