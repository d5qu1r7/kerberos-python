import os
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_aes_key() -> bytes:
    """
    Generates a random AES key (32 bytes for AES-256).
    
    Returns:
        bytes: The generated AES key.
    """
    return os.urandom(32)

def encrypt_object(data: object, key: bytes) -> bytes:
    """
    Encrypts a python object using AES-256 CBC mode and includes the IV in the result.
    
    Args:
        data (object): The object to encrypt
        key (bytes): The AES key (32 bytes for AES-256)
    
    Returns:
        bytes: The IV prepended to the encrypted data
    """
    # Generate a random IV
    iv = os.urandom(16)

    # Serialize the object using pickle
    data_bytes = pickle.dumps(data)
    
    # Create AES-256 cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data to a multiple of 16 bytes
    pad_length = 16 - len(data_bytes) % 16
    padded_data = data_bytes + bytes([pad_length] * pad_length)
    
    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Prepend the IV to the encrypted data
    return iv + encrypted_data

def decrypt_object(encrypted_data: bytes, key: bytes) -> object:
    """
    Decrypts AES-256 encrypted data with an IV prepended to it, back into the original python object.
    
    Args:
        encrypted_data (bytes): The IV prepended to the encrypted data.
        key (bytes): The AES key (32 bytes for AES-256).
    
    Returns:
        object: The original python object after decryption.
    """
    # Extract the IV from the beginning of the encrypted data
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    
    # Create AES-256 cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]
    
    # Deserialize the data back into the original python object
    deserialized_data = pickle.loads(decrypted_data)
    return deserialized_data