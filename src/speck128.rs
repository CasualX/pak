/*!
Speck 128/128.
*/

use super::{Key, Block};

macro_rules! R {
	($x:expr, $y:expr, $k:expr) => {
		$x = $x.rotate_right(8).wrapping_add($y) ^ $k;
		$y = $y.rotate_left(3) ^ $x;
	};
}
macro_rules! IR {
	($x:expr, $y:expr, $k:expr) => {
		$y = ($y ^ $x).rotate_right(3);
		$x = ($x ^ $k).wrapping_sub($y).rotate_left(8);
	};
}

const ROUNDS: usize = 32;

pub fn encrypt(block: Block, key: &Key) -> Block {
	let [mut y, mut x] = block;
	let &[mut b, mut a] = key;
	for i in 0..ROUNDS {
		R!(y, x, b);
		R!(a, b, i as u64);
	}
	[y, x]
}
pub fn decrypt(block: Block, key: &Key) -> Block {
	let mut round_keys = [0; ROUNDS];
	let &[mut b, mut a] = key;
	for i in 0..ROUNDS {
		round_keys[i] = b;
		R!(a, b, i as u64);
	}
	let [mut y, mut x] = block;
	for i in (0..ROUNDS).rev() {
		IR!(y, x, round_keys[i]);
	}
	[y, x]
}

#[test]
fn test_roundtrip() {
	let key = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
	let plaintext = [0x6c61766975716520, 0x7469206564616d20];
	let ciphertext = encrypt(plaintext, &key);
	assert_eq!(plaintext, decrypt(ciphertext, &key));
}
