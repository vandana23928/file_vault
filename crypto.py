import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import hashlib

class CryptoVault:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)

    def generate_key_pair(self, password=None):
        """Generate a new key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Save private key
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # Save public key
        pem_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write keys to files
        with open(os.path.join(self.key_dir, "private.pem"), "wb") as f:
            f.write(pem_private)
        with open(os.path.join(self.key_dir, "public.pem"), "wb") as f:
            f.write(pem_public)

    def _derive_key(self, password, salt):
        """Derive an AES key from a password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        return kdf.derive(password.encode() if isinstance(password, str) else password)

    def encrypt_file(self, input_path, public_key_path, password=None):
        try:
            # Generate a random AES key
            aes_key = os.urandom(32)
            salt = os.urandom(16)

            # Read the file content
            with open(input_path, "rb") as f:
                file_content = f.read()

            # Calculate file hash
            file_hash = hashlib.sha256(file_content).digest()

            # Load public key
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

            # Encrypt AES key with RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )

            # Prepare AES encryption
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()

            # Write encrypted file
            output_path = f"{input_path}.enc"
            with open(output_path, "wb") as outfile:
                # Write header
                outfile.write(salt + iv + encrypted_aes_key + file_hash)
                
                # Write encrypted content
                padded_data = padder.update(file_content) + padder.finalize()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                outfile.write(encrypted_data)

            return output_path

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_path, private_key_path, password=None):
        try:
            # Read encrypted file
            with open(input_path, "rb") as infile:
                salt = infile.read(16)
                iv = infile.read(16)
                encrypted_aes_key = infile.read(512)
                stored_hash = infile.read(32)
                encrypted_content = infile.read()

            # Load private key
            with open(private_key_path, "rb") as key_file:
                key_data = key_file.read()
                try:
                    private_key = serialization.load_pem_private_key(
                        key_data,
                        password=password.encode() if password else None,
                        backend=default_backend()
                    )
                except ValueError as e:
                    if "password" in str(e).lower():
                        if password:
                            raise ValueError("Incorrect password for private key")
                        else:
                            raise ValueError("Private key is encrypted. Password required.")

            # Decrypt AES key
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )

            # Decrypt file content
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            unpadder = sym_padding.PKCS7(128).unpadder()

            # Decrypt and unpad
            decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
            decrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()

            # Verify file integrity
            computed_hash = hashlib.sha256(decrypted_content).digest()
            if computed_hash != stored_hash:
                raise ValueError("File integrity check failed")

            # Write decrypted file
            output_path = input_path[:-4] if input_path.endswith(".enc") else f"{input_path}.dec"
            with open(output_path, "wb") as outfile:
                outfile.write(decrypted_content)

            return output_path

        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
