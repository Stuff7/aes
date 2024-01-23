mod consts;

use consts::*;
use std::{
  fs, io,
  ops::{Index, IndexMut},
  path::Path,
  time::{SystemTime, UNIX_EPOCH},
};

struct State<'a>(&'a mut [u8]);

impl<'a> Index<(usize, usize)> for State<'a> {
  type Output = u8;

  fn index(&self, index: (usize, usize)) -> &Self::Output {
    &self.0[index.0 * 4 + index.1]
  }
}

impl<'a> IndexMut<(usize, usize)> for State<'a> {
  fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
    &mut self.0[index.0 * 4 + index.1]
  }
}

pub struct AESContext {
  round_key: [u8; KEY_EXPANSION_LEN],
  pub iv: [u8; BLOCK_LEN],
}

impl AESContext {
  /// Creates a new AES context with a randomly generated Initialization Vector (IV)
  /// and a round key derived from a password using the AES key expansion algorithm.
  pub fn new(password: &str) -> Self {
    Self {
      round_key: derive_round_keys(&key_from_password(password)),
      iv: generate_iv(),
    }
  }

  pub fn refresh_iv(&mut self) {
    self.iv = generate_iv();
  }

  /// Encrypts the given buffer (`buf`) using Cipher Block Chaining (CBC) mode and prepends the IV.
  ///
  /// # Arguments
  ///
  /// * `buf` - A mutable reference to the buffer to be encrypted. The result is prepended with the IV.
  ///
  /// # Example
  ///
  /// ```
  /// let mut aes = aes::AESContext::new(key);
  /// let mut data = aes::read_as_block("data");
  /// aes.encrypt_with_iv(&mut data);
  /// ```
  pub fn encrypt_with_iv(&mut self, buf: &mut Vec<u8>) {
    self.encrypt(buf);
    buf.splice(0..0, self.iv.iter().copied());
  }

  /// Decrypts the given buffer (`buf`) using Cipher Block Chaining (CBC) mode and a prepended IV.
  ///
  /// # Arguments
  ///
  /// * `buf` - A mutable reference to the buffer containing the IV and encrypted data.
  ///
  /// # Example
  ///
  /// ```
  /// let mut aes = aes::AESContext::new(key);
  /// let mut data = aes::read_as_block("IV-prepended-ciphertext");
  /// aes.decrypt_with_iv(&mut data);
  /// ```
  pub fn decrypt_with_iv(&mut self, buf: &mut Vec<u8>) {
    self.iv.copy_from_slice(&buf.drain(..BLOCK_LEN).collect::<Vec<_>>());
    self.decrypt(buf);
  }

  /// Encrypts the given buffer (`buf`) using Cipher Block Chaining (CBC) mode.
  ///
  /// The IV used for encryption is managed internally by the AES instance.
  ///
  /// # Arguments
  ///
  /// * `buf` - A mutable reference to the buffer to be encrypted in-place.
  ///
  /// # Example
  ///
  /// ```
  /// let mut aes = aes::AESContext::new(key); // You will need to store the iv yourself, from aes.iv
  /// let mut data = aes::read_as_block("data");
  /// aes.encrypt(&mut data);
  /// ```
  pub fn encrypt(&mut self, buf: &mut [u8]) {
    let og_iv = self.iv;
    for i in (0..buf.len()).step_by(BLOCK_LEN) {
      let curr_buf = &mut buf[i..];
      self.xor_iv(curr_buf);
      self.cipher(&mut State(curr_buf));
      self.iv.copy_from_slice(&curr_buf[..BLOCK_LEN]);
    }
    self.iv = og_iv;
  }

  /// Decrypts the given buffer (`buf`) using Cipher Block Chaining (CBC) mode.
  ///
  /// Note: You need to set the IV manually before calling this method. Use `decrypt_with_iv`
  /// if the IV is embedded in the buffer.
  ///
  /// # Arguments
  ///
  /// * `buf` - A mutable reference to the buffer to be decrypted in-place.
  ///
  /// # Example
  ///
  /// ```
  /// let mut aes = aes::AESContext::new(key);
  /// let mut data = aes::read_as_block("ciphertext");
  /// aes.iv = iv; // IV the ciphertext was encrypted with
  /// aes.decrypt(&mut data);
  /// ```
  pub fn decrypt(&mut self, buf: &mut [u8]) {
    let mut next_iv = [0; 16];
    for i in (0..buf.len()).step_by(BLOCK_LEN) {
      let curr_buf = &mut buf[i..];
      next_iv.copy_from_slice(&curr_buf[..BLOCK_LEN]);
      self.inv_cipher(&mut State(curr_buf));
      self.xor_iv(curr_buf);
      self.iv.copy_from_slice(&next_iv);
    }
  }

  fn cipher(&self, state: &mut State) {
    self.xor_round_key(0, state);

    let mut round = 1;
    loop {
      self.apply_sub_box(state);
      left_rotate_rows(state);

      if round == ROUND_COUNT {
        break;
      }

      shuffle_state_columns(state);
      self.xor_round_key(round, state);
      round += 1;
    }

    self.xor_round_key(ROUND_COUNT, state);
  }

  fn inv_cipher(&self, state: &mut State) {
    let mut round = ROUND_COUNT - 1;

    self.xor_round_key(ROUND_COUNT, state);

    loop {
      right_rotate_rows(state);
      apply_inv_sub_box(state);
      self.xor_round_key(round, state);

      if round == 0 {
        break;
      }

      inv_shuffle_state_columns(state);
      round -= 1;
    }
  }

  fn xor_round_key(&self, round: usize, state: &mut State) {
    for i in 0..4 {
      for j in 0..4 {
        (*state)[(i, j)] ^= self.round_key[(round * STATE_COLUMNS * 4) + (i * STATE_COLUMNS) + j];
      }
    }
  }

  fn apply_sub_box(&self, state: &mut State) {
    for i in 0..4 {
      for j in 0..4 {
        (*state)[(j, i)] = SUBSTITUTION_BOX[(*state)[(j, i)] as usize];
      }
    }
  }

  fn xor_iv(&self, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate().take(BLOCK_LEN) {
      *b ^= self.iv[i];
    }
  }
}

pub fn read_as_block<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
  let mut buf = fs::read(path)?;
  vec_to_block(&mut buf)?;
  Ok(buf)
}

pub fn vec_to_block(buf: &mut Vec<u8>) -> io::Result<()> {
  buf.resize(ceil_to_factor(buf.len(), 16), 0);
  Ok(())
}

fn generate_iv() -> [u8; BLOCK_LEN] {
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Failed to generate initialization vector")
    .as_nanos() as usize;

  let mut seed = seed ^ ((&seed as *const usize) as usize);
  let mut result = [0u8; 16];

  for (i, n) in result.iter_mut().enumerate() {
    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
    *n = (seed >> (8 * (i % 8))) as u8;
  }

  result
}

fn derive_round_keys(key: &[u8]) -> [u8; KEY_EXPANSION_LEN] {
  let mut round_key = [0; KEY_EXPANSION_LEN];
  let mut tmp_array = [0; 4];

  for i in 0..KEY_WORD_COUNT {
    round_key[i * 4] = key[i * 4];
    round_key[(i * 4) + 1] = key[(i * 4) + 1];
    round_key[(i * 4) + 2] = key[(i * 4) + 2];
    round_key[(i * 4) + 3] = key[(i * 4) + 3];
  }

  for i in KEY_WORD_COUNT..STATE_COLUMNS * (ROUND_COUNT + 1) {
    let k = (i - 1) * 4;
    tmp_array[0] = round_key[k];
    tmp_array[1] = round_key[k + 1];
    tmp_array[2] = round_key[k + 2];
    tmp_array[3] = round_key[k + 3];

    if i % KEY_WORD_COUNT == 0 {
      let u8tmp: u8 = tmp_array[0];
      tmp_array[0] = tmp_array[1];
      tmp_array[1] = tmp_array[2];
      tmp_array[2] = tmp_array[3];
      tmp_array[3] = u8tmp;

      tmp_array[0] = SUBSTITUTION_BOX[tmp_array[0] as usize];
      tmp_array[1] = SUBSTITUTION_BOX[tmp_array[1] as usize];
      tmp_array[2] = SUBSTITUTION_BOX[tmp_array[2] as usize];
      tmp_array[3] = SUBSTITUTION_BOX[tmp_array[3] as usize];

      tmp_array[0] ^= ROUND_CONSTS[i / KEY_WORD_COUNT];
    }

    if i % KEY_WORD_COUNT == 4 {
      tmp_array[0] = SUBSTITUTION_BOX[tmp_array[0] as usize];
      tmp_array[1] = SUBSTITUTION_BOX[tmp_array[1] as usize];
      tmp_array[2] = SUBSTITUTION_BOX[tmp_array[2] as usize];
      tmp_array[3] = SUBSTITUTION_BOX[tmp_array[3] as usize];
    }

    let j = i * 4;
    let k = (i - KEY_WORD_COUNT) * 4;
    round_key[j] = round_key[k] ^ tmp_array[0];
    round_key[j + 1] = round_key[k + 1] ^ tmp_array[1];
    round_key[j + 2] = round_key[k + 2] ^ tmp_array[2];
    round_key[j + 3] = round_key[k + 3] ^ tmp_array[3];
  }

  round_key
}

// Encryption
fn left_rotate_rows(state: &mut State) {
  let mut tmp;

  tmp = (*state)[(0, 1)];
  (*state)[(0, 1)] = (*state)[(1, 1)];
  (*state)[(1, 1)] = (*state)[(2, 1)];
  (*state)[(2, 1)] = (*state)[(3, 1)];
  (*state)[(3, 1)] = tmp;

  tmp = (*state)[(0, 2)];
  (*state)[(0, 2)] = (*state)[(2, 2)];
  (*state)[(2, 2)] = tmp;

  tmp = (*state)[(1, 2)];
  (*state)[(1, 2)] = (*state)[(3, 2)];
  (*state)[(3, 2)] = tmp;

  tmp = (*state)[(0, 3)];
  (*state)[(0, 3)] = (*state)[(3, 3)];
  (*state)[(3, 3)] = (*state)[(2, 3)];
  (*state)[(2, 3)] = (*state)[(1, 3)];
  (*state)[(1, 3)] = tmp;
}

fn shuffle_state_columns(state: &mut State) {
  let mut tmp1;
  let mut tmp2;
  let mut tmp3;
  for i in 0..4 {
    tmp3 = (*state)[(i, 0)];
    tmp1 = (*state)[(i, 0)] ^ (*state)[(i, 1)] ^ (*state)[(i, 2)] ^ (*state)[(i, 3)];
    tmp2 = (*state)[(i, 0)] ^ (*state)[(i, 1)];
    tmp2 = galois_field_double(tmp2);
    (*state)[(i, 0)] ^= tmp2 ^ tmp1;
    tmp2 = (*state)[(i, 1)] ^ (*state)[(i, 2)];
    tmp2 = galois_field_double(tmp2);
    (*state)[(i, 1)] ^= tmp2 ^ tmp1;
    tmp2 = (*state)[(i, 2)] ^ (*state)[(i, 3)];
    tmp2 = galois_field_double(tmp2);
    (*state)[(i, 2)] ^= tmp2 ^ tmp1;
    tmp2 = (*state)[(i, 3)] ^ tmp3;
    tmp2 = galois_field_double(tmp2);
    (*state)[(i, 3)] ^= tmp2 ^ tmp1;
  }
}

// Decryption
fn right_rotate_rows(state: &mut State) {
  let mut tmp;

  tmp = (*state)[(3, 1)];
  (*state)[(3, 1)] = (*state)[(2, 1)];
  (*state)[(2, 1)] = (*state)[(1, 1)];
  (*state)[(1, 1)] = (*state)[(0, 1)];
  (*state)[(0, 1)] = tmp;

  tmp = (*state)[(0, 2)];
  (*state)[(0, 2)] = (*state)[(2, 2)];
  (*state)[(2, 2)] = tmp;

  tmp = (*state)[(1, 2)];
  (*state)[(1, 2)] = (*state)[(3, 2)];
  (*state)[(3, 2)] = tmp;

  tmp = (*state)[(0, 3)];
  (*state)[(0, 3)] = (*state)[(1, 3)];
  (*state)[(1, 3)] = (*state)[(2, 3)];
  (*state)[(2, 3)] = (*state)[(3, 3)];
  (*state)[(3, 3)] = tmp;
}

fn apply_inv_sub_box(state: &mut State) {
  for i in 0..4 {
    for j in 0..4 {
      (*state)[(j, i)] = INV_SUBSTITUTION_BOX[(*state)[(j, i)] as usize];
    }
  }
}

fn inv_shuffle_state_columns(state: &mut State) {
  for i in 0..4 {
    let a = (*state)[(i, 0)];
    let b = (*state)[(i, 1)];
    let c = (*state)[(i, 2)];
    let d = (*state)[(i, 3)];

    (*state)[(i, 0)] =
      galois_multiplication(a, 0x0e) ^ galois_multiplication(b, 0x0b) ^ galois_multiplication(c, 0x0d) ^ galois_multiplication(d, 0x09);
    (*state)[(i, 1)] =
      galois_multiplication(a, 0x09) ^ galois_multiplication(b, 0x0e) ^ galois_multiplication(c, 0x0b) ^ galois_multiplication(d, 0x0d);
    (*state)[(i, 2)] =
      galois_multiplication(a, 0x0d) ^ galois_multiplication(b, 0x09) ^ galois_multiplication(c, 0x0e) ^ galois_multiplication(d, 0x0b);
    (*state)[(i, 3)] =
      galois_multiplication(a, 0x0b) ^ galois_multiplication(b, 0x0d) ^ galois_multiplication(c, 0x09) ^ galois_multiplication(d, 0x0e);
  }
}

fn galois_field_double(x: u8) -> u8 {
  (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn galois_multiplication(x: u8, y: u8) -> u8 {
  ((y & 1) * x)
    ^ ((y >> 1 & 1) * galois_field_double(x))
    ^ ((y >> 2 & 1) * galois_field_double(galois_field_double(x)))
    ^ ((y >> 3 & 1) * galois_field_double(galois_field_double(galois_field_double(x))))
}

fn key_from_password(password: &str) -> Vec<u8> {
  let mut key = password.as_bytes().to_vec();
  key.resize(ceil_to_factor(key.len(), 16).max(32), 0);
  key
}

fn ceil_to_factor(n: usize, m: usize) -> usize {
  (n + m - 1) & !(m - 1)
}
