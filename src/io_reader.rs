use std::io::{self, Read};
use crate::*;

/// Reads a PAK file from file stream.
///
/// Returns `InvalidData` if the file does not encode a PAK file.
pub fn read<F: Read>(mut file: F, key: &Key) -> io::Result<Vec<Block>> {
	// Read and decrypt the header block
	let mut header = Header::zeroed();
	file.read_exact(header.as_bytes_mut())?;
	let info = crypt::decrypt_header(&header, key);
	if info.version != InfoHeader::VERSION {
		return Err(io::Error::from(io::ErrorKind::InvalidData));
	}
	// Use information from the header to calculate the total size of the PAK file
	// This code assumes the directory is the very last thing in the PAK file
	let total_blocks = usize::max(Header::BLOCKS_LEN, info.directory.offset as usize + info.directory.size as usize * Descriptor::BLOCKS_LEN);
	let mut blocks = vec![Block::default(); total_blocks];
	// Copy the header into the output since it's already read from the file
	// Then read the rest of the PAK file
	blocks[..Header::BLOCKS_LEN].as_bytes_mut().copy_from_slice(header.as_bytes());
	file.read_exact(blocks[Header::BLOCKS_LEN..].as_bytes_mut())?;
	Ok(blocks)
}

/*
pub struct IoReader<F: Read + Seek> {
	file: F,
	key: Key,
	info: InfoHeader,
}

impl<F: Read + Seek> IoReader<F> {
	pub fn new(mut file: F, key: &Key) -> io::Result<IoReader<F>> {
		file.seek(SeekFrom::Start(0))?;

		let mut header = Header::zeroed();
		file.read_exact(header.as_bytes_mut())?;

		let info = crypt::decrypt_header(&header, key);
		Ok(IoReader { file, key: *key, info })
	}

	pub fn find(&self, path: &[u8]) -> Option<Descriptor> {
		unimplemented!()
	}
}
*/
