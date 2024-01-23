# Rust AES

A lightweight implementation of the Advanced Encryption Standard (AES) algorithm in Cipher Block Chaining (CBC) mode in Rust.

# Usage

### As a Library

#### Read the data

To ensure the AES encryption/decryption works properly, the data size needs to be a multiple of 16

```rust
// You can use `read_as_block` to read it from a file with the correct size.
let mut buf = aes::read_as_block("file-input")?;
```

```rust
// Alternatively, if the data is already in memory, use `vec_to_block` to resize it in-place.
let mut buf = vec![1, 2, 3];
aes::vec_to_block(buf)?;
```

#### Set up the AES context and generate a random Initialization Vector (IV)

```rust
let mut ctx = aes::AESContext::new("Your secret password");
```

#### Encrypt/Decrypt with embedded IV

```rust
// Encrypts the data in-place, and prepends the context's `ctx` Initialization Vector (IV) to the buffer `buf`.
ctx.encrypt_with_iv(&mut buf);
// Strips the prepended IV from the buffer `buf`, then decrypts the remaining data in-place.
ctx.decrypt_with_iv(&mut buf);
```

#### Encrypt/Decrypt without embedded IV

```rust
// Encrypts the data in-place.
ctx.encrypt(&mut buf);
// Decrypts the data in-place.
ctx.decrypt(&mut buf);
```
### As a Binary

```bash
cargo run "path/to/input/file" -d "save/decrypted/input/file/here" -e "save/encrypted/input/file/here"
```
