use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::path::Path;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use sha2::{Sha256, Digest};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};

// Define the size of the buffer used for file operations (1 MB)
const BUFFER_SIZE: usize = 1024 * 1024;

// Struct to represent a disassembled instruction
#[derive(Clone, Debug)]
struct Instruction {
    op_code: String,
    address: i64,
    operands: String,
}

impl Instruction {
    // Constructor for the Instruction struct
    fn new(op_code: String, address: i64, operands: String) -> Self {
        Self { op_code, address, operands }
    }

    // Convert the instruction to a string representation
    fn to_string(&self) -> String {
        format!("{} {:08X} {}", self.op_code, self.address, self.operands)
    }
}

// Calculate the SHA256 hash of a file, reading it in chunks
fn calculate_file_hash<R: Read>(reader: &mut R) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(hasher.finalize().into())
}

// Disassemble a file into a vector of Instructions, reading in chunks
fn streaming_disassemble<R: Read>(reader: &mut R) -> io::Result<Vec<Instruction>> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut instructions = Vec::new();
    let mut address = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // Process each 4-byte chunk as an instruction
        for chunk in buffer[..bytes_read].chunks(4) {
            let op_code = format!("OP{:02X}", address);
            let operands = format!("OPERAND{:02X}", address);
            instructions.push(Instruction::new(op_code, address as i64, operands));
            address += chunk.len() as i64;
        }
    }

    Ok(instructions)
}

// Normalize the assembly code by replacing addresses with a placeholder
fn normalize(assembly_code: &[Instruction]) -> Vec<Instruction> {
    assembly_code.iter().map(|instruction| {
        Instruction::new(
            instruction.op_code.clone(),
            0,
            instruction.operands.replace(&format!("{:08X}", instruction.address), "SYMREF"),
        )
    }).collect()
}

// Generate a diff between old and new code
fn generate_diff(old_code: &[Instruction], new_code: &[Instruction]) -> Vec<String> {
    let mut diff = Vec::new();
    let max_length = old_code.len().max(new_code.len());
    for i in 0..max_length {
        if i >= old_code.len() {
            // New instruction added
            diff.push(format!("+{}", new_code[i].to_string()));
        } else if i >= new_code.len() {
            // Old instruction removed
            diff.push(format!("-{}", old_code[i].to_string()));
        } else if old_code[i].to_string() != new_code[i].to_string() {
            // Instruction changed
            diff.push(format!("~{} -> {}", old_code[i].to_string(), new_code[i].to_string()));
        }
    }
    diff
}

// Extract address changes between old and new disassembled code
fn extract_address_changes(old_disassembled: &[Instruction], new_disassembled: &[Instruction]) -> Vec<i64> {
    old_disassembled.iter().zip(new_disassembled.iter())
        .map(|(old, new)| new.address - old.address)
        .collect()
}

// Create a streaming diff between two files
fn create_streaming_diff(old_file_path: &Path, new_file_path: &Path, output_path: &Path) -> io::Result<()> {
    let mut old_file = BufReader::new(File::open(old_file_path)?);
    let mut new_file = BufReader::new(File::open(new_file_path)?);
    let mut output_file = BufWriter::new(File::create(output_path)?);

    // Calculate and write original file hash
    old_file.seek(SeekFrom::Start(0))?;
    let original_file_hash = calculate_file_hash(&mut old_file)?;
    output_file.write_all(&original_file_hash)?;

    // Disassemble files
    old_file.seek(SeekFrom::Start(0))?;
    let old_disassembled = streaming_disassemble(&mut old_file)?;
    let new_disassembled = streaming_disassemble(&mut new_file)?;

    // Normalize disassembled code
    let old_normalized = normalize(&old_disassembled);
    let new_normalized = normalize(&new_disassembled);

    // Generate diff and extract address changes
    let diff = generate_diff(&old_normalized, &new_normalized);
    let address_changes = extract_address_changes(&old_disassembled, &new_disassembled);

    // Write diff
    output_file.write_u32::<LittleEndian>(diff.len() as u32)?;
    for d in diff {
        output_file.write_u32::<LittleEndian>(d.len() as u32)?;
        output_file.write_all(d.as_bytes())?;
    }

    // Write address changes
    output_file.write_u32::<LittleEndian>(address_changes.len() as u32)?;
    for change in address_changes {
        output_file.write_i64::<LittleEndian>(change)?;
    }

    output_file.flush()?;
    Ok(())
}

// Compress the diff file using gzip
fn compress_diff(input_path: &Path, output_path: &Path) -> io::Result<()> {
    let input_file = BufReader::new(File::open(input_path)?);
    let output_file = BufWriter::new(File::create(output_path)?);
    let mut encoder = GzEncoder::new(output_file, Compression::default());
    io::copy(&mut BufReader::new(input_file), &mut encoder)?;
    encoder.finish()?;
    Ok(())
}

// Decompress the diff file from gzip
fn decompress_diff(input_path: &Path, output_path: &Path) -> io::Result<()> {
    let input_file = BufReader::new(File::open(input_path)?);
    let output_file = BufWriter::new(File::create(output_path)?);
    let mut decoder = GzDecoder::new(input_file);
    io::copy(&mut decoder, &mut BufWriter::new(output_file))?;
    Ok(())
}

// Apply a streaming patch to a file
fn apply_streaming_patch(file_path: &Path, patch_path: &Path) -> io::Result<()> {
    let mut file = File::options().read(true).write(true).open(file_path)?;
    let mut patch_file = BufReader::new(File::open(patch_path)?);

    // Read and verify file hash
    let mut file_hash = [0u8; 32];
    patch_file.read_exact(&mut file_hash)?;
    let actual_file_hash = calculate_file_hash(&mut file)?;
    if file_hash != actual_file_hash {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File hash mismatch"));
    }

    // Read diff
    let diff_count = patch_file.read_u32::<LittleEndian>()?;
    let mut diff = Vec::new();
    for _ in 0..diff_count {
        let diff_len = patch_file.read_u32::<LittleEndian>()?;
        let mut diff_bytes = vec![0u8; diff_len as usize];
        patch_file.read_exact(&mut diff_bytes)?;
        diff.push(String::from_utf8(diff_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    }

    // Read address changes
    let change_count = patch_file.read_u32::<LittleEndian>()?;
    let mut address_changes = Vec::new();
    for _ in 0..change_count {
        address_changes.push(patch_file.read_i64::<LittleEndian>()?);
    }

    // Apply patch (simplified version, expand for real use)
    for (i, change) in address_changes.iter().enumerate() {
        file.seek(SeekFrom::Start((i * 4) as u64))?;
        let mut value = file.read_i32::<LittleEndian>()?;
        value += *change as i32;
        file.seek(SeekFrom::Start((i * 4) as u64))?;
        file.write_i32::<LittleEndian>(value)?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage:");
        println!("To create a patch: oxidiff create <oldFilePath> <newFilePath>");
        println!("To apply a patch: oxidiff apply <fileToUpdatePath> <patchPath>");
        return Ok(());
    }

    match args[1].as_str() {
        "create" => {
            if args.len() != 4 {
                println!("Usage: oxidiff create <oldFilePath> <newFilePath>");
                return Ok(());
            }
            let old_file_path = Path::new(&args[2]);
            let new_file_path = Path::new(&args[3]);

            // Create uncompressed diff
            let uncompressed_diff_path = Path::new("uncompressed_diff.bin");
            create_streaming_diff(old_file_path, new_file_path, uncompressed_diff_path)?;
            println!("Uncompressed diff created");

            // Compress the diff
            let compressed_diff_path = Path::new("compressed_diff.bin");
            compress_diff(uncompressed_diff_path, compressed_diff_path)?;
            println!("Compressed diff saved to: {:?}", compressed_diff_path);

            // Clean up uncompressed diff
            std::fs::remove_file(uncompressed_diff_path)?;
        }
        "apply" => {
            if args.len() != 4 {
                println!("Usage: oxidiff apply <fileToUpdatePath> <patchPath>");
                return Ok(());
            }
            let file_to_update_path = Path::new(&args[2]);
            let compressed_patch_path = Path::new(&args[3]);

            // Decompress the patch
            let uncompressed_patch_path = Path::new("temp_uncompressed_patch.bin");
            decompress_diff(compressed_patch_path, uncompressed_patch_path)?;

            // Apply the patch
            match apply_streaming_patch(file_to_update_path, uncompressed_patch_path) {
                Ok(_) => println!("Patch applied successfully"),
                Err(e) => println!("Failed to apply patch: {}", e),
            }

            // Clean up temporary uncompressed patch
            std::fs::remove_file(uncompressed_patch_path)?;
        }
        _ => println!("Invalid command. Use 'create' or 'apply'."),
    }

    Ok(())
}