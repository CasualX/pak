/*!
 */

use std::{fmt, mem, ops, ptr, slice};
use dataview::Pod;

// Must be a macro, inline function does not work
#[cfg(debug_assertions)]
macro_rules! unsafe_assume {
	($cond:expr) => {
		assert!($cond);
	};
}
#[cfg(not(debug_assertions))]
macro_rules! unsafe_assume {
	($cond:expr) => {
		if !$cond {
			unsafe { std::hint::unreachable_unchecked() }
		}
	};
}

mod speck128;
mod crypt;
pub mod directory;

mod memory_reader;
mod memory_editor;
pub use self::memory_reader::{MemoryReader, MemoryReadIter};
pub use self::memory_editor::{MemoryEditor, MemoryEditFile};

mod io_reader;
pub use self::io_reader::read;

pub type Block = [u64; 2];
pub type Key = [u64; 2];

pub const BLOCK_SIZE: usize = mem::size_of::<Block>();
pub const KEY_SIZE: usize = mem::size_of::<Key>();

/// Section object.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Section {
	/// Offset in blocks to the start of the section.
	pub offset: u32,
	/// Length in blocks of the section.
	pub size: u32,
	/// Cryptographic nonce used for this section.
	pub nonce: Block,
}
impl Section {
	fn range_usize(&self) -> ops::Range<usize> {
		self.offset as usize..(self.offset.wrapping_add(self.size)) as usize
	}
}
unsafe impl Pod for Section {}

#[inline]
unsafe fn append_raw<T, F: FnMut(*mut [T])>(vec: &mut Vec<T>, len: usize, mut f: F) {
	vec.reserve(len);
	let data = vec.as_mut_ptr().offset(vec.len() as isize);
	let raw = ptr::slice_from_raw_parts_mut(data, len);
	f(raw);
	vec.set_len(vec.len() + len);
}

fn bytes2blocks(byte_size: u32) -> u32 {
	if byte_size == 0 { 0 } else { (byte_size - 1) / BLOCK_SIZE as u32 + 1 }
}

//----------------------------------------------------------------

macro_rules! impl_blocks {
	($ty:ty; $blocks_len:expr) => {
		impl $ty {
			pub const BLOCKS_LEN: usize = $blocks_len;
		}

		impl AsRef<[Block; $blocks_len]> for $ty {
			fn as_ref(&self) -> &[Block; $blocks_len] {
				unsafe { &*(self as *const _ as *const _) }
			}
		}
		impl AsRef<$ty> for [Block; $blocks_len] {
			fn as_ref(&self) -> &$ty {
				unsafe { &*(self as *const _ as *const _) }
			}
		}
		impl AsMut<[Block; $blocks_len]> for $ty {
			fn as_mut(&mut self) -> &mut [Block; $blocks_len] {
				unsafe { &mut *(self as *mut _ as *mut _) }
			}
		}
		impl AsMut<$ty> for [Block; $blocks_len] {
			fn as_mut(&mut self) -> &mut $ty {
				unsafe { &mut *(self as *mut _ as *mut _) }
			}
		}
		impl From<[Block; $blocks_len]> for $ty {
			fn from(blocks: [Block; $blocks_len]) -> $ty {
				unsafe { mem::transmute(blocks) }
			}
		}
		impl From<$ty> for [Block; $blocks_len] {
			fn from(header: $ty) -> [Block; $blocks_len] {
				unsafe { mem::transmute(header) }
			}
		}

	};
}

//----------------------------------------------------------------

/// The PAK file info header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct InfoHeader {
	/// Version info value, should be equal to `Header::VERSION_INFO`.
	pub version: u32,
	/// Padding...
	pub unused: [u32; 1],
	/// The section object describing the location of the directory.
	///
	/// Special note: the section size specifies the number of `Descriptors` not the number of blocks.
	pub directory: Section,
}
unsafe impl Pod for InfoHeader {}

impl InfoHeader {
	/// Current expected version number.
	pub const VERSION: u32 = 0;
}

impl_blocks!(InfoHeader; mem::size_of::<InfoHeader>() / BLOCK_SIZE);

/// The PAK file header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Header {
	/// 256-Bit HMAC.
	pub hmac: [u32; 8],
	/// Initializing vector for decrypting the info header.
	pub iv: Block,
	/// Version information and directory section.
	pub info: InfoHeader,
}
unsafe impl Pod for Header {}

impl_blocks!(Header; mem::size_of::<Header>() / BLOCK_SIZE);

//----------------------------------------------------------------

#[derive(Copy, Clone, Default, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Descriptor {
	pub content_type: u32,
	pub content_size: u32,
	pub section: Section,
	pub name_buf: [u8; 32],
}
unsafe impl Pod for Descriptor {}
impl Descriptor {
	/// Creates a new empty descriptor with the given name, content type and size.
	///
	/// The descriptor is a directory descriptor if its `content_type` is zero.
	/// Its `content_size` specifies the number of children contained in the directory.
	///
	/// The descriptor is a file descriptor if its `content_type` is non-zero.
	/// The interpretation of this non-zero type is left to the user of the API.
	/// Its `content_size` specifies the size of the file in bytes.
	pub fn new(name: &[u8], content_type: u32, content_size: u32) -> Descriptor {
		let mut desc = Descriptor {
			content_type,
			content_size,
			..Descriptor::default()
		};
		desc.set_name(name);
		desc
	}
	/// Creates an empty file descriptor.
	pub fn file(name: &[u8]) -> Descriptor {
		Descriptor::new(name, 1, 0)
	}
	/// Creates a directory descriptor and given the number of children.
	pub fn dir(name: &[u8], len: u32) -> Descriptor {
		Descriptor::new(name, 0, len)
	}
	fn name_len(&self) -> usize {
		self.name_buf.len() - self.name_buf[self.name_buf.len() - 1] as usize
	}
	fn set_name_len(&mut self, len: usize) {
		self.name_buf[self.name_buf.len() - 1] = (self.name_buf.len() - len) as u8;
	}
	/// Gets the descriptor's name encoded in the `name_buf`.
	pub fn name(&self) -> &[u8] {
		let len = usize::min(self.name_len(), 31);
		&self.name_buf[..len]
	}
	/// Sets the descriptors's name by encoding it in the `name_buf`.
	///
	/// Names longer than the name buffer's length are cut off.
	pub fn set_name(&mut self, name: &[u8]) {
		let len = usize::min(name.len(), 31);
		self.set_name_len(len);
		self.name_buf[..len].copy_from_slice(&name[..len]);
	}
	/// Is this a directory descriptor?
	pub fn is_dir(&self) -> bool {
		self.content_type == 0
	}
	/// Is this a file descriptor?
	pub fn is_file(&self) -> bool {
		self.content_type != 0
	}
}
impl fmt::Debug for Descriptor {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Descriptor")
			.field("content_type", &self.content_type)
			.field("content_size", &self.content_type)
			.field("section_offset", &format_args!("{:#x}", self.section.offset))
			.field("section_size", &format_args!("{:#x}", self.section.size))
			.field("section_nonce", &format_args!("[{:#x}, {:#x}]", self.section.nonce[0], self.section.nonce[1]))
			.field("name", &std::str::from_utf8(self.name()).unwrap_or("ERR"))
			.finish()
	}
}

impl_blocks!(Descriptor; mem::size_of::<Descriptor>() / BLOCK_SIZE);

//----------------------------------------------------------------
