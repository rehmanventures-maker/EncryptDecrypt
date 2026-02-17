import hashlib
import base64

def rot13(s):
    """Simple ROT13 implementation (reversible)"""
    result = ''
    for c in s:
        if 'a' <= c <= 'z':
            result += chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= c <= 'Z':
            result += chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += c
    return result

def encrypt_string(user_input):
    """Encrypt input string using SHA-256, SHA-1, Base64, and ROT13"""
    
    sha256_hash = hashlib.sha256(user_input.encode()).hexdigest()
    sha1_hash = hashlib.sha1(user_input.encode()).hexdigest()
    base64_encoded = base64.b64encode(user_input.encode()).decode()
    rot13_encoded = rot13(user_input)

    return {
        "SHA-256": sha256_hash,
        "SHA-1": sha1_hash,
        "Base64": base64_encoded,
        "ROT13": rot13_encoded
    }

def decrypt_string():
    """Decrypt Base64 or ROT13 strings"""
    print("\n=== Decryption ===")
    choice = input("Choose method to decrypt (Base64/ROT13): ").strip().lower()
    if choice not in ["base64", "rot13"]:
        print("Invalid choice. Only Base64 and ROT13 can be decrypted.")
        return

    encrypted = input("Enter the encrypted string: ").strip()
    if not encrypted:
        print("No input provided. Exiting.")
        return

    if choice == "base64":
        try:
            decoded = base64.b64decode(encrypted.encode()).decode()
            print(f"Decrypted Base64: {decoded}")
        except Exception as e:
            print(f"Error decoding Base64: {e}")
    elif choice == "rot13":
        decoded = rot13(encrypted)
        print(f"Decrypted ROT13: {decoded}")

def main():
    print("=== String Encryption CLI Tool ===")
    user_input = input("Enter a string to encrypt: ").strip()

    if not user_input:
        print("No input provided. Exiting.")
        return

    results = encrypt_string(user_input)
    print("\nEncrypted Results:\n")
    for method, value in results.items():
        print(f"{method:<10}: {value}")

    # Optionally decrypt Base64 or ROT13
    decrypt_choice = input("\nDo you want to decrypt a string? (y/n): ").strip().lower()
    if decrypt_choice == 'y':
        decrypt_string()
    else:
        print("Exiting program.")

if __name__ == "__main__":
    main()
