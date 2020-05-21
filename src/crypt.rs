use std::{mem, slice};
use dataview::Pod;
use crate::*;

pub fn xor(a: Block, b: Block) -> Block {
	[a[0] ^ b[0], a[1] ^ b[1]]
}
pub fn counter(nonce: &Block, ctr: usize) -> Block {
	[nonce[0], nonce[1].wrapping_add(ctr as u64)]
}
pub fn random(blocks: &mut [Block]) {
	let dest = unsafe { slice::from_raw_parts_mut(blocks.as_mut_ptr() as *mut u8, mem::size_of_val(blocks)) };
	getrandom::getrandom(dest).unwrap();
}

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum Pad {
	Zero = 0x00,
	Transparent = 0xff,
}

//----------------------------------------------------------------
// Header

pub fn decrypt_header_inplace(header: &mut Header, key: &Key) {
	// Decrypt in CBC mode of operation
	let fs = header.as_mut();
	fs[4] = speck128::decrypt(xor(fs[4], fs[3]), key);
	fs[3] = speck128::decrypt(xor(fs[3], fs[2]), key);
}
pub fn encrypt_header_inplace(header: &mut Header, key: &Key) {
	// Encrypt in CBC mode of operation
	let fs = header.as_mut();
	fs[3] = xor(speck128::encrypt(fs[3], key), fs[2]);
	fs[4] = xor(speck128::encrypt(fs[4], key), fs[3]);
}
pub fn decrypt_header(encrypted_header: &Header, key: &Key) -> InfoHeader {
	let src = encrypted_header.as_ref();
	let dest = [
		speck128::decrypt(xor(src[3], src[2]), key),
		speck128::decrypt(xor(src[4], src[3]), key),
	];
	unsafe { mem::transmute(dest) }
}

#[test]
fn test_crypt_header_roundtrip() {
	let header = Header {
		hmac: [0; 8],
		iv: [1, 999],
		info: InfoHeader {
			version: 0x42,
			unused: [0x13],
			directory: Section {
				offset: 64,
				size: 32,
				nonce: [42, 13],
			},
		},
	};
	let key = [133, 422];
	let mut crypted = header;
	encrypt_header_inplace(&mut crypted, &key);
	assert_eq!(header.info, decrypt_header(&crypted, &key));
	decrypt_header_inplace(&mut crypted, &key);
	assert_eq!(header, crypted);
}

//----------------------------------------------------------------
// Directory

pub fn encrypt(src: &[Block], nonce: &Block, key: &Key, dest: &mut [Block]) {
	assert_eq!(src.len(), dest.len());
	for i in 0..src.len() {
		dest[i] = xor(src[i], speck128::encrypt(counter(nonce, i), key));
	}
}
pub fn decrypt(src: &[Block], nonce: &Block, key: &Key, dest: &mut [Block]) {
	assert_eq!(src.len(), dest.len());
	for i in 0..src.len() {
		dest[i] = xor(src[i], speck128::encrypt(counter(nonce, i), key));
	}
}

pub fn crypt_inplace(blocks: &mut [Block], nonce: &Block, key: &Key) {
	for i in 0..blocks.len() {
		blocks[i] = xor(blocks[i], speck128::encrypt(counter(nonce, i), key));
	}
}

pub fn decrypt_desc(encrypted_desc: &Descriptor, nonce: &Block, key: &Key) -> Descriptor {
	let mut dest = <[Block; Descriptor::BLOCKS_LEN]>::default();
	decrypt(encrypted_desc.as_ref(), nonce, key, &mut dest);
	unsafe { mem::transmute(dest) }
}

pub fn decrypt_dir(blocks: &[Block], dir_section: &Section, key: &Key) -> Vec<Descriptor> {
	unimplemented!()
}

pub fn encrypt_dir_inplace(dir: &mut [Descriptor], nonce: &Block, key: &Key) {
	crypt_inplace(dir.as_data_view_mut().slice_tail_mut(0), nonce, key);
}
pub unsafe fn encrypt_dir(src: &[Descriptor], nonce: &Block, key: &Key, dest: &mut [Block]) {
	encrypt(src.as_data_view().slice_tail(0), nonce, key, dest);
}

#[test]
fn test_crypt_desc_roundtrip() {
	let desc = Descriptor::file(b"hello world");
	let key = [133, 422];
	let nonce = [31415, 2781];
	let mut crypted = desc;
	crypted = decrypt_desc(&crypted, &nonce, &key);
	assert_eq!(desc, decrypt_desc(&crypted, &nonce, &key));
	crypted = decrypt_desc(&crypted, &nonce, &key);
	assert_eq!(desc, crypted);
}

//----------------------------------------------------------------
// Data

pub fn decrypt_data(blocks: &[Block], nonce: &Block, key: &Key, mut byte_offset: usize, mut dest: &mut [u8]) {
	// Range check to ensure the dest blocks are large enough
	let byte_end = byte_offset + dest.len();
	if blocks.as_bytes().get(byte_offset..byte_end).is_none() {
		return;
	}
	if dest.is_empty() {
		return;
	}
	// Calculate the range of blocks we'll need to decrypt
	let mut block_start = byte_offset / BLOCK_SIZE;
	let block_end = byte_end / BLOCK_SIZE;
	let block_offset = byte_offset - block_start * BLOCK_SIZE;
	unsafe_assume!(block_start < blocks.len());
	unsafe_assume!(block_end <= blocks.len());
	unsafe_assume!(block_offset < BLOCK_SIZE);
	// If they're the same then we're decrypting a subsection of a single block
	if block_start == block_end {
		unsafe_assume!(dest.len() <= BLOCK_SIZE - block_offset);
		decrypt_subdata(&blocks[block_start], counter(nonce, block_start), key, block_offset, dest);
		return;
	}
	// Spans at least two blocks
	unsafe_assume!(dest.len() >= BLOCK_SIZE - block_offset);
	// Decrypt the prefix given byte offset
	if block_offset != 0 {
		decrypt_subdata(&blocks[block_start], counter(nonce, block_start), key, block_offset, &mut dest[..BLOCK_SIZE - block_offset]);
		// Adjust the start parameters after the prefix
		let prefix_size = BLOCK_SIZE - block_offset;
		dest = &mut dest[prefix_size..];
		block_start += 1;
		byte_offset += prefix_size;
	}
	// At this point the byte offset is aligned to block size
	debug_assert_eq!(byte_offset % BLOCK_SIZE, 0);
	// Decrypt the blocks in the middle
	for block_i in block_start..block_end {
		unsafe_assume!(block_i < blocks.len());
		let block = xor(blocks[block_i], speck128::encrypt(counter(nonce, block_i), key));
		unsafe_assume!(dest.len() >= BLOCK_SIZE);
		block.as_data_view().copy_into(0, &mut dest[..BLOCK_SIZE]);
		dest = &mut dest[BLOCK_SIZE..];
		byte_offset += BLOCK_SIZE;
	}
	// Decrypt the tail block
	if dest.len() != 0 {
		unsafe_assume!(block_end < blocks.len());
		unsafe_assume!(dest.len() < BLOCK_SIZE);
		decrypt_subdata(&blocks[block_end], counter(nonce, block_end), key, 0, dest);
	}
}
fn decrypt_subdata(block_ref: &Block, nonce: Block, key: &Key, byte_offset: usize, dest: &mut [u8]) {
	let xor_key = speck128::encrypt(nonce, key);
	let block = xor(*block_ref, xor_key);
	// block.as_data_view().copy_into(byte_offset, dest);
	for i in byte_offset..usize::min(BLOCK_SIZE, byte_offset + dest.len()) {
		dest[i - byte_offset] = block.as_bytes()[i];
	}
}

pub fn encrypt_data(blocks: &mut [Block], nonce: &Block, key: &Key, mut byte_offset: usize, mut src: &[u8], pad: Pad) {
	// Range check to ensure the dest blocks are large enough
	let byte_end = byte_offset + src.len();
	if blocks.as_bytes().get(byte_offset..byte_end).is_none() {
		return;
	}
	if src.is_empty() {
		return;
	}
	// Calculate the range of blocks we'll need to encrypt
	let mut block_start = byte_offset / BLOCK_SIZE;
	let block_end = byte_end / BLOCK_SIZE;
	let block_offset = byte_offset - block_start * BLOCK_SIZE;
	unsafe_assume!(block_start < blocks.len());
	unsafe_assume!(block_end <= blocks.len());
	unsafe_assume!(block_offset < BLOCK_SIZE);
	// If they're the same then we're encrypting a subsection of a single block
	if block_start == block_end {
		unsafe_assume!(src.len() <= BLOCK_SIZE - block_offset);
		encrypt_subdata(&mut blocks[block_start], counter(nonce, block_start), key, block_offset, src, pad);
		return;
	}
	// Spans at least two blocks
	unsafe_assume!(src.len() >= BLOCK_SIZE - block_offset);
	// Encrypt the prefix given byte offset
	if block_offset != 0 {
		encrypt_subdata(&mut blocks[block_start], counter(nonce, block_start), key, block_offset, &src[..BLOCK_SIZE - block_offset], pad);
		// Adjust the start parameters after the prefix
		let prefix_size = BLOCK_SIZE - block_offset;
		src = &src[prefix_size..];
		block_start += 1;
		byte_offset += prefix_size;
	}
	// At this point the byte offset is aligned to block size
	debug_assert_eq!(byte_offset % BLOCK_SIZE, 0);
	// Encrypt the blocks in the middle
	for block_i in block_start..block_end {
		unsafe_assume!(src.len() >= BLOCK_SIZE);
		let block = src.as_data_view().copy(0);
		unsafe_assume!(block_i < blocks.len());
		blocks[block_i] = xor(block, speck128::encrypt(counter(nonce, block_i), key));
		src = &src[BLOCK_SIZE..];
		byte_offset += BLOCK_SIZE;
	}
	// Encrypt the tail block
	if src.len() != 0 {
		unsafe_assume!(block_end < blocks.len());
		unsafe_assume!(src.len() < BLOCK_SIZE);
		encrypt_subdata(&mut blocks[block_end], counter(nonce, block_end), key, 0, src, pad);
	}
}
fn encrypt_subdata(block_mut: &mut Block, nonce: Block, key: &Key, byte_offset: usize, src: &[u8], pad: Pad) {
	let xor_key = speck128::encrypt(nonce, key);
	let mut block = match pad { Pad::Transparent => xor(*block_mut, xor_key), Pad::Zero => Block::default() };
	// block.as_data_view_mut().write(byte_offset, src);
	for i in byte_offset..usize::min(BLOCK_SIZE, byte_offset + src.len()) {
		block.as_bytes_mut()[i] = src[i - byte_offset];
	}
	*block_mut = xor(block, xor_key);
}
pub fn encrypt_zero(blocks: &mut [Block], nonce: &Block, key: &Key) {
	for i in 0..blocks.len() {
		blocks[i] = speck128::encrypt(counter(nonce, i), key);
	}
}
pub fn reencrypt_data(blocks: &mut [Block], old_nonce: &Block, new_nonce: &Block, old_key: &Key, new_key: &Key) {
	for i in 0..blocks.len() {
		let block = xor(blocks[i], speck128::encrypt(counter(old_nonce, i), old_key));
		blocks[i] = xor(block, speck128::encrypt(counter(new_nonce, i), new_key));
	}
}

#[test]
fn test_crypt_subdata() {
	let mut src = [0; 15];
	getrandom::getrandom(&mut src).unwrap();
	let key = &[42, 13];
	let nonce = &[0x42, 0x13];
	for i in 0..15 {
		let mut blocks = [[0u64; 2]; 1];
		encrypt_data(&mut blocks, nonce, key, i % 8, &src[i..], Pad::Zero);
		let mut dest = [0; 15];
		decrypt_data(&blocks, nonce, key, i % 8, &mut dest[i..]);
		assert_eq!(&src[i..], &dest[i..]);
	}
}
#[test]
fn test_crypt_data() {
	let mut src = [0; 31];
	getrandom::getrandom(&mut src).unwrap();
	let key = &[13, 42];
	let nonce = &[0x13, 0x42];
	for i in 0..16 {
		let mut blocks = [[0u64; 2]; 4];
		encrypt_data(&mut blocks, nonce, key, i, &src, Pad::Zero);
		let mut dest = [0; 31];
		decrypt_data(&blocks, nonce, key, i, &mut dest);
		assert_eq!(&src, &dest);
	}
}
