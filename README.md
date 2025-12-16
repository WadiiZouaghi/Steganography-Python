# Stego Project — Hide and Extract Secrets in Images

A powerful Python steganography tool that hides and extracts secret files from images using LSB (Least Significant Bit) encoding with optional password encryption.

## Features

- **Hide files in images**: Embed any file type (documents, text, archives, etc.) into PNG/JPEG images
- **Extract hidden files**: Recover embedded files from stego-packed images
- **Password protection**: Encrypt hidden files with ChaCha20Poly1305 AEAD cipher
- **Secure key derivation**: Uses Argon2 for password-based key derivation
- **Random distribution**: Distributes ciphertext bits pseudo-randomly across image using seeded PRNG
- **GUI & CLI modes**: User-friendly graphical interface and command-line interface
- **No file corruption**: Original image quality remains virtually unchanged

## Installation

### Requirements

- Python 3.8+
- pip (Python package manager)

### Dependencies

```bash
pip install pillow cryptography argon2-cffi customtkinter numpy
```

- **Pillow**: Image manipulation
- **cryptography**: ChaCha20Poly1305 encryption
- **argon2-cffi**: Argon2 password hashing
- **customtkinter**: Modern GUI framework
- **numpy**: Fast array operations

## Usage

### GUI Mode

Run the application with the graphical interface:

```bash
python stego.py --gui
```

Or simply run without arguments:

```bash
python stego.py
```

**GUI Features:**
- Switch between **Hide** and **Extract** modes with tabs
- Live image preview and capacity information
- Drag-and-drop file selection
- Optional password protection
- Real-time progress indication
- Activity logging

### CLI Mode

#### Hide a secret file

```bash
python stego.py hide --image <image_path> --secret <secret_file> --output <output_path> [--password <password>]
```

**Example:**
```bash
python stego.py hide --image photo.png --secret document.pdf --output stego_photo.png --password mypassword
```

#### Extract a hidden file

```bash
python stego.py extract --image <stego_image> --output <output_dir> [--password <password>]
```

**Example:**
```bash
python stego.py extract --image stego_photo.png --output . --password mypassword
```

#### Command-line options

- `hide` / `extract`: Operation mode (required)
- `--image`: Path to image file (required)
- `--secret`: Path to secret file to hide (required for hide mode)
- `--output`: Output file/directory path (required)
- `--password`: Password for encryption (optional)
- `--verbose`: Print detailed operation information (optional flag)

## How It Works

### Steganography Method

1. **LSB Encoding**: Embeds data in the least significant bit of RGB color channels
2. **Capacity**: Each pixel (3 channels) can hold 3 bits of data (with current settings)
3. **Header**: Stores encryption flag, salt/nonce lengths, and ciphertext length
4. **Random Distribution**: Ciphertext bits are distributed pseudo-randomly using a seeded PRNG

### Encryption Flow

**Hiding:**
1. Generate random salt and nonce
2. Derive encryption key from password using Argon2
3. Encrypt payload with ChaCha20Poly1305
4. Prepend filename length and original filename to encrypted data
5. Create binary header with metadata
6. Embed header sequentially, then distribute ciphertext randomly across image

**Extracting:**
1. Read header from LSB of first pixel bytes
2. Extract salt and nonce from sequential LSB bits
3. Regenerate encryption key using same salt and provided password
4. Recover ciphertext bits using same PRNG seed
5. Decrypt payload and extract filename
6. Write recovered file to output directory

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| Magic Number | `STG2` |
| Salt Length | 16 bytes |
| Nonce Length | 12 bytes |
| Key Length | 32 bytes |
| LSB per Channel | 1 bit |
| Channels | 3 (RGB) |
| Argon2 Time | 3 |
| Argon2 Memory | 65,536 KB |
| Argon2 Parallelism | 1 |
| Cipher | ChaCha20Poly1305 |

## Capacity Calculator

```
Image size (pixels) × 3 (channels) × 1 (LSB per channel) ÷ 8 = Capacity (bytes)

Example: 1920×1080 image
1920 × 1080 × 3 × 1 ÷ 8 = 777,600 bytes (~760 KB)
```

## File Format

**Header Structure:**
```
Magic (4 bytes) | Enc Flag (1) | Salt Len (1) | Nonce Len (1) | Ciphertext Len (4)
```

**Full Payload:**
```
Header | Salt | Nonce | Filename Length (4) | Filename | Encrypted File Content
```

## Security Considerations

- **Encryption**: ChaCha20Poly1305 provides authenticated encryption (AEAD)
- **Key Derivation**: Argon2 is resistant to GPU/ASIC attacks
- **Randomness**: Uses Python's secure `os.urandom()` for cryptographic randomness
- **Stego Detection**: Statistically detectable with image analysis tools (intended for stealth, not security against forensic analysis)
- **Password Strength**: Security depends on password entropy; use strong passwords

## Limitations

- Image quality: Minimally affected but technically altered
- Capacity: Limited to ~40% of image pixel data size
- Detection: Not resistant to statistical steganalysis
- Filenames: Preserved as plaintext (use encryption to protect filename)

## Error Handling

- Invalid header magic → "Invalid stego magic"
- Wrong password → Decryption fails with exception
- Corrupted image → "Image does not contain enough embedded bits"
- Oversized payload → "Payload too large to hide"

## License

MIT License — Feel free to use, modify, and distribute.

## Contributing

Contributions are welcome! Feel free to report bugs, suggest features, or submit pull requests.

---

**Author**: Wadii Zouaghi 
**Last Updated**: 2025
