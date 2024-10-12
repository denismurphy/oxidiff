# 🦀 Oxidiff

Binary diffing and patching tool.

## Features

- 🚀 Streaming-based operations for handling large files efficiently
- 🧠 Intelligent assembly code normalization for meaningful diffs
- 🔒 SHA256 hash verification for file integrity
- 🗜️ GZIP compression for compact patch files
- 🔄 Bi-directional functionality: create and apply patches
- 💻 Cross-platform support (Windows, macOS, Linux)

### Prerequisites

- Rust 1.55 or later

## Usage

Oxidiff supports two main operations: creating patches and applying patches.

### Creating a Patch

To create a patch between an old version and a new version of a file:

```
oxidiff create <old_file_path> <new_file_path>
```

This will generate a compressed patch file named `compressed_diff.bin` in the current directory.

### Applying a Patch

To apply a patch to update a file:

```
oxidiff apply <file_to_update_path> <patch_file_path>
```

This will update the file in place.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
