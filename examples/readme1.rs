
fn main() {
	let key = &[13, 42];

	// Create the editor object to create PAK files in memory.
	let mut edit = pak::MemoryEditor::new();

	// This file contains 65 bytes filled with `0xCF`.
	let data = &[0xCF; 65];

	// Let's create a file `foo` under a directory `sub`.
	// If a file already exists by this name it will be overwritten.
	edit.create_file(b"sub/foo", data, key);

	// When done the editor object can be finalized and returns the encrypted PAK file as a `Vec<Block>`.
	// It also returns the unencrypted directory for final inspection if desired.
	let (pak, dir) = edit.finish(key);

	// Print the directory.
	print!("The directory:\n\n```\n{}```\n\n", pak::directory::to_string(&dir, &pak::directory::Art::ASCII));

	// Print the PAK file itself.
	print!("The RAW data:\n\n```\n{:x?}\n```\n", pak);

	// Create the reader object to inspect PAK files in memory.
	let read = pak::MemoryReader::from_blocks(&pak, key);
	// Find the file created earlier.
	let desc = read.find(b"sub/foo").unwrap();
	// Read its contents into a `Vec<u8>`.
	let content = read.read_data(&desc);
	// Check that it still matches the expected content.
	assert_eq!(content, &data[..]);
}
