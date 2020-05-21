use crate::*;

/// PAK editor with memory buffers.
#[derive(Clone, Debug)]
pub struct MemoryEditor {
	blocks: Vec<Block>,
	dir: Vec<Descriptor>,
}
impl MemoryEditor {
	/// Creates a new `MemoryEditor` instance.
	pub fn new() -> MemoryEditor {
		// The blocks must contain at least space for the header ref$1
		let blocks = vec![Block::default(); Header::BLOCKS_LEN];
		let dir = Vec::new();
		MemoryEditor { blocks, dir }
	}

	/// Creates a new `MemoryEditor` instance from existing encrypted PAK file.
	pub fn from_blocks(mut blocks: Vec<Block>, key: &Key) -> MemoryEditor {
		let dir;
		// The blocks must contain at least space for the header ref$1
		if blocks.len() < Header::BLOCKS_LEN {
			blocks.resize(Header::BLOCKS_LEN, Block::default());
			dir = Vec::new();
		}
		else {
			// Decrypt the header to find and decrypt the directory
			let header = crypt::decrypt_header(unsafe { &*(blocks.as_ptr() as *const Header) }, key);
			dir = crypt::decrypt_dir(&blocks, &header.directory, key);
			// Avoid creating extra garbage if the directory is at the end
			if blocks.len() == header.directory.offset as usize + header.directory.size as usize * Descriptor::BLOCKS_LEN {
				blocks.truncate(header.directory.offset as usize);
			}
		}
		MemoryEditor { blocks, dir }
	}

	/// Creates a file at the given path.
	///
	/// The file is assigned a content_type of `1`.
	/// A new section is allocated and the contents are encrypted and written into the section.
	pub fn create_file(&mut self, path: &[u8], content: &[u8], key: &Key) {
		self.edit_file(path).set_content(1, content.len() as u32).allocate_data().init_data(content, key);
	}

	/// Creates a symbolic link from the path to the given file descriptor.
	pub fn create_symlink(&mut self, path: &[u8], file_desc: &Descriptor) {
		self.edit_file(path).set_content(file_desc.content_type, file_desc.content_size).set_section(&file_desc.section);
	}

	/// Creates a file descriptor at the given path.
	/// Any missing parent directories are automatically created.
	pub fn edit_file(&mut self, path: &[u8]) -> MemoryEditFile<'_> {
		let desc = directory::create(&mut self.dir, path);
		let blocks = &mut self.blocks;
		MemoryEditFile { desc, blocks }
	}

	/// Creates a directory descriptor at the given path.
	/// Any missing parent directories are automatically created.
	pub fn create_dir(&mut self, path: &[u8]) {
		let desc = directory::create(&mut self.dir, path);
		desc.content_type = 0;
		desc.content_size = 0;
		desc.section = Section::default();
	}

	/// Removes a descriptor at the given path.
	///
	/// Returns `false` if no descriptor is found at the given path.
	/// The directory remains unchanged, the output argument deleted is untouched.
	///
	/// Returns `true` if a file descriptor is found at the given path.
	/// The descriptor is removed and optionally copied to the deleted output argument.
	///
	/// Returns `true` if a directory descriptor is found at the given path.
	/// The descriptor is removed and optionally copied to the deleted output argument.
	/// All the direct children of the removed directory are moved to its parent directory.
	pub fn remove(&mut self, path: &[u8], deleted: Option<&mut Descriptor>) -> bool {
		directory::remove(&mut self.dir, path, deleted)
	}

	/// Compacts the referenced blocks from file descriptors.
	///
	/// Any file descriptors with an invalid section address have their address zeroed.
	pub fn gc(&mut self) {
		let mut blocks = vec![Block::default(); Header::BLOCKS_LEN];

		for desc in &mut self.dir {
			if desc.is_file() {
				let offset = blocks.len();
				if let Some(contents) = self.blocks.get(desc.section.range_usize()) {
					blocks.extend_from_slice(contents);
					desc.section.offset = offset as u32;
				}
				else {
					// Not much to do when we find an invalid descriptor...
					desc.section = Section::default();
				}
			}
		}

		self.blocks = blocks;
	}

	/// Finish editing the PAK file.
	///
	/// Initializes the header, encrypts the directory and appends it to the blocks.
	/// Returns the encrypted PAK file and the unencrypted directory for inspection.
	pub fn finish(self, key: &Key) -> (Vec<Block>, Vec<Descriptor>) {
		let MemoryEditor { mut blocks, mut dir } = self;

		// Finalize the directory
		directory::update_dir_address(&mut dir);

		// Initialize the header and pick random iv and nonce
		let directory;
		{
			// SAFETY: When initialized the blocks contain space for at least the header, see ref$1
			// SAFETY: Carefully avoid aliasing problems because this mut reference isn't constrained because raw pointer dereference
			let header_mut = unsafe { &mut *(blocks.as_mut_ptr() as *mut Header) };
			crypt::random(header_mut.as_mut());
			header_mut.info.version = InfoHeader::VERSION;
			header_mut.info.unused = [0];

			// Calculate offset for the directory
			header_mut.info.directory.offset = blocks.len() as u32;
			header_mut.info.directory.size = dir.len() as u32;
			directory = header_mut.info.directory;
			crypt::encrypt_header_inplace(header_mut, key);
		}

		// Allocate space for the directory and encrypt it
		unsafe {
			let dir_blocks_len = directory.size as usize * Descriptor::BLOCKS_LEN;
			append_raw(&mut blocks, dir_blocks_len, |raw| {
				crypt::encrypt_dir(&dir, &directory.nonce, key, &mut *raw);
			});
		}

		// Return the produced PAK file
		(blocks, dir)
	}
}

/// Memory file editor.
///
/// This type provides advanced capabilities for editing a file.
/// Incorrect usage may result in corrupted file contents or even corrupt the entire PAK file.
pub struct MemoryEditFile<'a> {
	desc: &'a mut Descriptor,
	blocks: &'a mut Vec<Block>,
}
impl<'a> MemoryEditFile<'a> {
	/// Sets the content type and size for this file descriptor.
	///
	/// Note that a content type of `0` gets overwritten by a type of `1`.
	pub fn set_content(&mut self, content_type: u32, content_size: u32) -> &mut MemoryEditFile<'a> {
		self.desc.content_type = u32::max(1, content_type); // zero is reserved for directory descriptors...
		self.desc.content_size = content_size;
		return self;
	}
	/// Gets the content type for this file descriptor.
	#[inline]
	pub fn content_type(&self) -> u32 {
		self.desc.content_type
	}
	/// Gets the content size for this file descriptor
	#[inline]
	pub fn content_size(&self) -> u32 {
		self.desc.content_size
	}
	/// Assigns an existing section object to this file descriptor.
	///
	/// This can be used to make different descriptors point to the same file contents.
	pub fn set_section(&mut self, section: &Section) -> &mut MemoryEditFile<'a> {
		self.desc.section = *section;
		return self;
	}
	/// Gets the section object for this file descriptor.
	#[inline]
	pub fn section(&self) -> &Section {
		&self.desc.section
	}
	/// Allocates and assigns space for the file contents.
	///
	/// The size allocated is defined by a previous call to `set_content`'s content_size argument.
	///
	/// The space allocated is logically uninitialized and must be initialized with a call to `init_data` or `init_zero`.
	pub fn allocate_data(&mut self) -> &mut MemoryEditFile<'a> {
		// Simple bump allocate from the blocks Vec
		self.desc.section.offset = self.blocks.len() as u32;
		self.desc.section.size = bytes2blocks(self.desc.content_size);

		// FIXME! How to handle overflow?
		// Currently it is simply ignored, this should panic when attempting to write into the allocation...
		// I mean, it's more likely to panic due to not having enough memory for the blocks in the first place, but still...
		if let Some(new_len) = self.blocks.len().checked_add(self.desc.section.size as usize) {
			// Zero initialization implies encrypting zeroes...
			unsafe {
				self.blocks.reserve(new_len);
				self.blocks.set_len(new_len);
			}
		}

		// Initialize a random nonce once upon allocation
		// Nonces should not be reused but this should be fine as there's no chance to observe the data while this `MemoryEditFile` instance lives
		crypt::random(slice::from_mut(&mut self.desc.section.nonce));

		return self;
	}
	/// Copies and encrypts the content with the given key into the address specified by this file descriptor.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn init_data(&mut self, content: &[u8], key: &Key) -> &mut MemoryEditFile<'a> {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];
		// Encrypt the content into blocks
		crypt::encrypt_data(blocks, &self.desc.section.nonce, key, 0, content, crypt::Pad::Zero);
		return self;
	}
	/// Initialize the contents with zeroes.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn zero_data(&mut self, key: &Key) -> &mut MemoryEditFile<'a> {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];
		// Zero the storage
		crypt::encrypt_zero(blocks, &self.desc.section.nonce, key);
		return self;
	}
	/// Copies and encrypts content to a subsection of the file.
	///
	/// The file must be initialized (either through `init_data` or `zero_data`) before it can be updated.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn copy_data(&mut self, byte_offset: usize, content: &[u8], key: &Key) -> &mut MemoryEditFile<'a> {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];
		// Encrypt the content into the blocks (assuming it already contains valid data)
		crypt::encrypt_data(blocks, &self.desc.section.nonce, key, byte_offset, content, crypt::Pad::Transparent);
		return self;
	}
	/// Reencrypts the content.
	///
	/// The file must be initialized (either through `init_data` or `zero_data`) before it can be updated.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn reencrypt_data(&mut self, old_key: &Key, new_key: &Key) {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];
		let old_nonce = self.desc.section.nonce;
		crypt::random(slice::from_mut(&mut self.desc.section.nonce));
		crypt::reencrypt_data(blocks, &old_nonce, &self.desc.section.nonce, old_key, new_key);
	}
}
