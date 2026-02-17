##🧪 Project Overview

This is a **Python CLI-based string encryption tool** designed for learning and practicing encryption standards.  
It allows users to input a string, encrypt it using multiple algorithms, and optionally decrypt reversible formats.  

**Supported Encryption Standards:**

- **SHA-256** (One-way hash)
- **SHA-1** (One-way hash)
- **Base64** (Reversible encoding)
- **ROT13** (Reversible character rotation)

**Decryption Support:**

- **Base64**
- **ROT13**

> SHA-1 and SHA-256 are cryptographic hashes and cannot be decrypted.

---

## 💻 Features

- Encrypt user input with multiple standards in a single run
- Display encryption results clearly in the terminal
- Decrypt Base64 and ROT13 encoded strings
- Fully CLI-based — no GUI required
- Simple, lightweight, and resume-friendly

---

## 🛠 Technology Stack

- Python 3.x
- `hashlib` for SHA-256 and SHA-1 hashing
- `base64` for encoding/decoding
- Custom ROT13 implementation


