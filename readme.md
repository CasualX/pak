PAK file
========

The PAK file is a lightweight encrypted archive inspired by the Quake PAK format.

Library
-------

WORK IN PROGRESS :)

Examples
--------

The following code shows how to create a new PAK file and add some content to it.

Try it out locally: `cargo run --example readme1`.

```rust
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
```

File layout
-----------

The layout of the PAK file is very simple.

* The header contains a version info number and the location of the directory.

  There is no way to know whether the blob of bytes is a valid PAK file without the correct key as everything is encrypted by design.

* The data containing the file contents.

  This is an opaque blob of bytes only decodable via information in the directory.

* The directory is a sequence of descriptors encoding a [light weight TLV structure](https://en.wikipedia.org/wiki/Type-length-value).

  File descriptors contain the location and a cryptographic nonce for accessing the file contents.
  Directory descriptors describe how many of the following descriptors are its children.

Security
--------

This library uses the [Speck cipher](https://en.wikipedia.org/wiki/Speck_\(cipher\)) in the 128/128 bit variant.

License
-------

Licensed under [MIT License](https://opensource.org/licenses/MIT), see [license.txt](license.txt).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
