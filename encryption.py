import os
import io
import zipfile
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# --- Key Generation and Serialization ---

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem

def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

def load_private_key(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)

# --- Symmetric Key Derivation ---

def derive_key_from_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# --- File Encryption/Decryption ---

def encrypt_file(file_data: bytes, rsa_public_key_pem: bytes, use_password=False, password: str = None):
    sym_key = Fernet.generate_key()
    fernet = Fernet(sym_key)
    encrypted_data = fernet.encrypt(file_data)

    public_key = load_public_key(rsa_public_key_pem)
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    salt = None
    if use_password and password:
        derived_key, salt = derive_key_from_password(password)
        fernet_pw = Fernet(derived_key)
        encrypted_sym_key = fernet_pw.encrypt(encrypted_sym_key)

    return {
        "encrypted_data": encrypted_data,
        "encrypted_sym_key": encrypted_sym_key,
        "salt": salt
    }

def decrypt_file(encrypted_data: bytes, encrypted_sym_key: bytes, rsa_private_key_pem: bytes, use_password=False, password: str = None, salt: bytes = None):
    if use_password and password and salt:
        derived_key, _ = derive_key_from_password(password, salt)
        fernet_pw = Fernet(derived_key)
        encrypted_sym_key = fernet_pw.decrypt(encrypted_sym_key)

    private_key = load_private_key(rsa_private_key_pem)
    sym_key = private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    fernet = Fernet(sym_key)
    return fernet.decrypt(encrypted_data)

# --- Folder Utilities ---

def zip_folder(folder_path: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=folder_path)
                zipf.write(full_path, arcname)
    buf.seek(0)
    return buf.read()

def unzip_folder(zip_bytes: bytes, extract_to: str):
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, 'r') as zipf:
        for file_info in zipf.infolist():
            target_path = os.path.join(extract_to, file_info.filename)
            abs_target = os.path.abspath(target_path)
            abs_extract = os.path.abspath(extract_to)
            if not abs_target.startswith(abs_extract):
                raise ValueError(f"Invalid file path: {target_path}")
            if file_info.is_dir():
                os.makedirs(target_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with zipf.open(file_info) as src, open(target_path, 'wb') as dest:
                    dest.write(src.read())
    return extract_to
