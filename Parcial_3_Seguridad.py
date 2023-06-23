import subprocess
import codecs
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def encrypt_string_openssl(input_string, password):
    salt = b'\x9a\x32\x54\x2a\x7c\x90\x0f\x43'
    password = password.encode()

    # Derive key from password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))[:32]  # Limit key size to 32 bytes

    # Generate random IV
    iv = os.urandom(16)

    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Encrypt the input string
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_string.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate IV and ciphertext
    encrypted_string = iv + ciphertext

    # Encode to base64
    encoded_string = base64.b64encode(encrypted_string).decode()

    return encoded_string

def decrypt_string_openssl(encrypted_string, password):
    salt = b'\x9a\x32\x54\x2a\x7c\x90\x0f\x43'
    password = password.encode()

    # Derive key from password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))[:32]  # Limit key size to 32 bytes

    # Decode base64 string
    encoded_string = encrypted_string.encode()
    encrypted_string = base64.b64decode(encoded_string)

    # Extract IV and ciphertext
    iv = encrypted_string[:16]
    ciphertext = encrypted_string[16:]

    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_data.decode()

def encrypt_string_cesar(input_string, shift):
    encrypted_string = ""
    for char in input_string:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_string += encrypted_char
        else:
            encrypted_string += char
    return encrypted_string

def decrypt_string_cesar(encrypted_string, shift):
    decrypted_string = ""
    for char in encrypted_string:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_string += decrypted_char
        else:
            decrypted_string += char
    return decrypted_string

def encrypt_string_hex(input_string):
    hex_encoded = codecs.encode(input_string.encode(), 'hex').decode()
    return hex_encoded

def decrypt_string_hex(hex_encrypted):
    try:
        decoded_bytes = codecs.decode(hex_encrypted, 'hex')
        decrypted_string = decoded_bytes.decode()
        return decrypted_string
    except:
        return None

while True:
    print("Seleccione una opción:")
    print("1. Encriptar cadena")
    print("2. Desencriptar cadena")
    print("3. Salir")
    option = input("Opción: ")

    if option == "1":
        input_string = input("Ingresa la cadena a encriptar: ")
        password = input("Ingresa la contraseña de encriptación: ")

        # Encriptación César
        shift = 3
        cesar_encrypted = encrypt_string_cesar(input_string, shift)

        # Cifrado hexadecimal
        hex_encrypted = encrypt_string_hex(cesar_encrypted)

        # Encriptación con OpenSSL
        openssl_encrypted = encrypt_string_openssl(hex_encrypted, password)

        print("Cadena original:", input_string)
        print("Cadena encriptada con OpenSSL:", openssl_encrypted)
        print("Cadena en Cesar:", encrypt_string_cesar(openssl_encrypted, shift))
        print("Cadena en hexadecimal:", encrypt_string_hex(encrypt_string_cesar(openssl_encrypted, shift)))
        print()
    elif option == "2":
        input_string = input("Ingresa la cadena encriptada con OpenSSL: ")
        password = input("Ingresa la contraseña de desencriptación: ")

        # Decodificar cadena encriptada con OpenSSL
        hex_encrypted = decrypt_string_openssl(input_string, password)

        if hex_encrypted is None:
            print("Contraseña incorrecta. Por favor, verifica la contraseña e intenta nuevamente.")
            print()
            continue

        # Decodificar cadena hexadecimal
        decrypted_string = decrypt_string_hex(hex_encrypted)

        if decrypted_string is None:
            print("Cadena hexadecimal inválida. Por favor, verifica la cadena e intenta nuevamente.")
            print()
            continue

        # Desencriptación César
        shift = 3
        decrypted_cesar = decrypt_string_cesar(decrypted_string, shift)

        print("Cadena encriptada con OpenSSL:", input_string)
        print("Cadena desencriptada:", decrypted_cesar)
        print("Cadena en Cesar:", encrypt_string_cesar(input_string, shift))
        print("Cadena en hexadecimal:", encrypt_string_hex(encrypt_string_cesar(input_string, shift)))
        print()
    elif option == "3":
        print("¡Hasta luego!")
        break
    else:
        print("Opción inválida. Por favor, selecciona una opción válida.")
        print()
