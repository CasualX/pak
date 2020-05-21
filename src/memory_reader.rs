use std::slice;
use crate::*;

fn read_directory<'a>(blocks: &'a [Block], info: &InfoHeader) -> &'a [Descriptor] {
	let dir_offset = info.directory.offset as usize;
	let dir_size = info.directory.size as usize;
	let directory = match blocks.get(dir_offset..dir_offset + dir_size * Descriptor::BLOCKS_LEN) {
		Some(directory) => directory,
		None => return &[],
	};
	unsafe {
		slice::from_raw_parts(directory.as_ptr() as *const Descriptor, dir_size)
	}
}

/// Memory directory iterator.
#[derive(Clone)]
pub struct MemoryReadIter<'a> {
	memory_reader: &'a MemoryReader<'a>,
	start: u32,
	end: u32,
}
impl<'a> Iterator for MemoryReadIter<'a> {
	type Item = Descriptor;
	fn next(&mut self) -> Option<Descriptor> {
		if self.start >= self.end {
			return None;
		}
		let desc = crypt::decrypt_desc(&self.memory_reader.directory[self.start as usize], &crypt::counter(&self.memory_reader.dirnonce, self.start as usize), &self.memory_reader.key);
		self.start = directory::next_sibling(&desc, self.start as usize, self.end as usize) as u32;
		Some(desc)
	}
}

/// Reads a PAK file from memory with on-the-fly decryption.
#[derive(Copy, Clone, Default)]
pub struct MemoryReader<'a> {
	blocks: &'a [Block],
	key: Key,
	directory: &'a [Descriptor],
	dirnonce: Block,
}
impl<'a> MemoryReader<'a> {
	/// Constructs a new `MemoryReader` from the blocks and key.
	///
	/// If the blocks are corrupt or the key is not valid an empty directory is returned instead.
	/// This means that this MemoryReader will behave as if it contains no files or directories.
	pub fn from_blocks(blocks: &'a [Block], key: &Key) -> MemoryReader<'a> {
		// If we don't have enough blocks for a header, just return an empty reader
		if blocks.len() < Header::BLOCKS_LEN {
			return MemoryReader { blocks, ..Default::default() }
		}
		// At this point we have at least Header::BLOCKS_LEN elements in the blocks so lets reinterpret cast it
		let header1 = unsafe { &*(blocks.as_ptr() as *const Header) };
		// Decrypt the header and extract the root section
		let header = crypt::decrypt_header(header1, key);
		// Figure out the directory and if it's invalid just return an empty one
		let directory = read_directory(blocks, &header);
		MemoryReader { blocks, key: *key, directory, dirnonce: header.directory.nonce }
	}
	/// Returns if this MemoryReader contains no files or directories.
	pub fn is_empty(&self) -> bool {
		self.directory.is_empty()
	}
	/// Finds a descriptor by its path.
	pub fn find(&self, path: &[u8]) -> Option<Descriptor> {
		directory::find_encrypted(self.directory, path, &self.dirnonce, &self.key)
	}
	/// Finds a descriptor by its path starting from the given root directory.
	pub fn find_sub(&self, root: &Descriptor, path: &[u8]) -> Option<Descriptor> {
		let subdir = &self.directory[root.section.range_usize()];
		let nonce = crypt::counter(&self.dirnonce, root.section.offset as usize * Descriptor::BLOCKS_LEN);
		directory::find_encrypted(subdir, path, &nonce, &self.key)
	}
	/// Returns if the descriptor is a valid file.
	///
	/// A valid file descriptor is defined by:
	///
	/// * Its content type is not equal to zero.
	/// * Its section address is within the range of the PAK file and does not point within the header.
	/// * Its content size fits within the section's address.
	pub fn is_valid_file(&self, desc: &Descriptor) -> bool {
		return
			desc.content_type != 0 &&
			desc.section.offset >= Header::BLOCKS_LEN as u32 &&
			self.blocks.get(desc.section.range_usize()).is_some() &&
			bytes2blocks(desc.content_size) <= desc.section.size;
	}
	/// Returns if the descriptor is a valid directory.
	///
	/// A valid directory descriptor is defined by:
	///
	/// * Its content type is equal to zero.
	/// * Its section address is within the range of the directory.
	/// * Its content size is equal to the section address size.
	pub fn is_valid_dir(&self, desc: &Descriptor) -> bool {
		return
			desc.content_type == 0 &&
			desc.section.size == desc.content_size &&
			self.directory.get(desc.section.range_usize()).is_some();
	}
	/// Decrypts the contents of the given file descriptor.
	///
	/// If given a directory descriptor an empty Vec is returned.
	/// If the descriptor is corrupt the returned Vec may contain zeroes.
	pub fn read_data(&self, desc: &Descriptor) -> Vec<u8> {
		if !desc.is_file() {
			return Vec::new();
		}
		let mut bytes = vec![0; desc.content_size as usize];
		if let Some(blocks) = self.blocks.get(desc.section.range_usize()) {
			crypt::decrypt_data(blocks, &desc.section.nonce, &self.key, 0, &mut bytes);
		}
		bytes
	}
	/// Decrypts the contents of the given file descriptor into the dest buffer.
	/// Given a byte offset into the file where to start decrypting.
	///
	/// If given a directory descriptor nothing is written to the dest buffer.
	/// If the descriptor is corrupt nothing may be written to the dest buffer.
	pub fn read_into(&self, desc: &Descriptor, byte_offset: usize, dest: &mut [u8]) {
		if !desc.is_file() {
			return;
		}
		if let Some(blocks) = self.blocks.get(desc.section.range_usize()) {
			crypt::decrypt_data(blocks, &desc.section.nonce, &self.key, byte_offset, dest);
		}
	}
	pub fn iter(&self, desc: &Descriptor) -> MemoryReadIter<'_> {
		MemoryReadIter {
			memory_reader: self,
			start: desc.section.offset,
			end: desc.section.offset + desc.section.size,
		}
	}
}
