import codecs
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# El código importa los módulos y las clases necesarias para la encriptación y desencriptación de datos.

def encrypt_string_openssl(input_string, password):
    salt = b'\x9a\x32\x54\x2a\x7c\x90\x0f\x43'
    password = password.encode()

    # Define una función llamada "encrypt_string_openssl" que recibe una cadena de texto de entrada y una contraseña.
    # Crea una sal (valor aleatorio) y convierte la contraseña a una codificación de bytes.

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))[:32]

    # Crea un objeto "PBKDF2HMAC" para derivar una clave a partir de la contraseña y la sal.
    # Configura el algoritmo de hash SHA256, el tamaño de la clave (32 bytes), la sal y el número de iteraciones.
    # Deriva la clave utilizando la contraseña y la sal.
    # Codifica la clave resultante en base64 y toma los primeros 32 bytes como clave final.

    iv = os.urandom(16)

    # Genera un vector de inicialización (IV) aleatorio de 16 bytes.

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Crea un objeto "Cipher" para el algoritmo AES en modo CBC, utilizando la clave y el IV generados.

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(input_string.encode()) + padder.finalize()

    # Crea un objeto "padder" para el padding PKCS7 de bloques de 128 bits.
    # Rellena la cadena de texto de entrada con el padding PKCS7.

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Crea un objeto "encryptor" para cifrar los datos utilizando el objeto "cipher".
    # Cifra los datos de entrada, incluyendo el padding, utilizando el "encryptor".

    encrypted_string = iv + ciphertext

    # Concatena el IV y el texto cifrado.

    encoded_string = base64.b64encode(encrypted_string).decode()

    # Codifica la cadena concatenada en base64 y la convierte a una representación de cadena.

    return encoded_string

    # Devuelve la cadena encriptada.

def decrypt_string_openssl(encrypted_string, password):
    salt = b'\x9a\x32\x54\x2a\x7c\x90\x0f\x43'
    password = password.encode()

    # Define una función llamada "decrypt_string_openssl" que recibe una cadena de texto encriptada y una contraseña.
    # Crea una sal (valor aleatorio) y convierte la contraseña a una codificación de bytes.

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))[:32]

    # Crea un objeto "PBKDF2HMAC" para derivar una clave a partir de la contraseña y la sal.
    # Configura el algoritmo de hash SHA256, el tamaño de la clave (32 bytes), la sal y el número de iteraciones.
    # Deriva la clave utilizando la contraseña y la sal.
    # Codifica la clave resultante en base64 y toma los primeros 32 bytes como clave final.

    encoded_string = encrypted_string.encode()
    encrypted_string = base64.b64decode(encoded_string)

    # Decodifica la cadena encriptada en base64.

    iv = encrypted_string[:16]
    ciphertext = encrypted_string[16:]

    # Extrae el IV y el texto cifrado.

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Crea un objeto "Cipher" para el algoritmo AES en modo CBC, utilizando la clave y el IV.

    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Crea un objeto "decryptor" para descifrar los datos utilizando el objeto "cipher".
    # Descifra el texto cifrado utilizando el "decryptor".

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    # Crea un objeto "unpadder" para eliminar el padding PKCS7.
    # Elimina el padding de los datos descifrados.

    return decrypted_data.decode()

    # Devuelve la cadena desencriptada.

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

    # Define una función llamada "encrypt_string_cesar" que recibe una cadena de texto de entrada y un desplazamiento.
    # Encripta la cadena de texto utilizando el cifrado César.

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

    # Define una función llamada "decrypt_string_cesar" que recibe una cadena de texto encriptada y un desplazamiento.
    # Desencripta la cadena de texto utilizando el cifrado César.

def encrypt_string_hex(input_string):
    hex_encoded = codecs.encode(input_string.encode(), 'hex').decode()
    return hex_encoded

    # Define una función llamada "encrypt_string_hex" que recibe una cadena de texto de entrada.
    # Codifica la cadena en hexadecimal.

def decrypt_string_hex(hex_encrypted):
    try:
        decoded_bytes = codecs.decode(hex_encrypted, 'hex')
        decrypted_string = decoded_bytes.decode()
        return decrypted_string
    except:
        return None

    # Define una función llamada "decrypt_string_hex" que recibe una cadena encriptada en hexadecimal.
    # Decodifica la cadena en hexadecimal y la convierte en una representación de cadena.

while True:
    print("Seleccione una opción:")
    print("1. Encriptar cadena")
    print("2. Desencriptar cadena")
    print("3. Salir")
    option = input("Opción: ")

    if option == "1":
        input_string = input("Ingresa la cadena a encriptar: ")
        password = input("Ingresa la contraseña de encriptación: ")

        # Solicita al usuario ingresar una cadena de texto y una contraseña para encriptar la cadena.

        shift = 3
        cesar_encrypted = encrypt_string_cesar(input_string, shift)

        # Establece el desplazamiento para el cifrado César en 3.
        # Encripta la cadena de texto utilizando el cifrado César.

        hex_encrypted = encrypt_string_hex(cesar_encrypted)

        # Codifica la cadena encriptada en hexadecimal.

        openssl_encrypted = encrypt_string_openssl(hex_encrypted, password)

        # Encripta la cadena encriptada en hexadecimal utilizando OpenSSL.

        print("Cadena original:", input_string)
        print("Cadena encriptada con OpenSSL:", openssl_encrypted)
        print("Cadena en Cesar:", encrypt_string_cesar(openssl_encrypted, shift))
        print("Cadena en hexadecimal:", encrypt_string_hex(encrypt_string_cesar(openssl_encrypted, shift)))
        print()

        # Imprime la cadena original, la cadena encriptada con OpenSSL, la cadena encriptada con César y la cadena en hexadecimal.

    elif option == "2":
        input_string = input("Ingresa la cadena encriptada con OpenSSL: ")
        password = input("Ingresa la contraseña de desencriptación: ")

        # Solicita al usuario ingresar una cadena de texto encriptada con OpenSSL y una contraseña para desencriptar la cadena.

        hex_encrypted = decrypt_string_openssl(input_string, password)

        # Desencripta la cadena encriptada con OpenSSL utilizando la contraseña proporcionada.

        if hex_encrypted is None:
            print("Contraseña incorrecta. Por favor, verifica la contraseña e intenta nuevamente.")
            print()
            continue

        # Si la contraseña es incorrecta, muestra un mensaje de error y continúa con el ciclo.

        decrypted_string = decrypt_string_hex(hex_encrypted)

        # Decodifica la cadena encriptada en hexadecimal.

        if decrypted_string is None:
            print("Cadena hexadecimal inválida. Por favor, verifica la cadena e intenta nuevamente.")
            print()
            continue

        # Si la cadena en hexadecimal es inválida, muestra un mensaje de error y continúa con el ciclo.

        shift = 3
        decrypted_cesar = decrypt_string_cesar(decrypted_string, shift)

        # Desencripta la cadena en hexadecimal utilizando el cifrado César.

        print("Cadena encriptada con OpenSSL:", input_string)
        print("Cadena desencriptada:", decrypted_cesar)
        print("Cadena en Cesar:", encrypt_string_cesar(input_string, shift))
        print("Cadena en hexadecimal:", encrypt_string_hex(encrypt_string_cesar(input_string, shift)))
        print()

        # Imprime la cadena encriptada con OpenSSL, la cadena desencriptada, la cadena en César y la cadena en hexadecimal.

    elif option == "3":
        print("¡Hasta luego!")
        break

        # Si la opción seleccionada es "3", muestra un mensaje de despedida y finaliza el programa.

    else:
        print("Opción inválida. Por favor, selecciona una opción válida.")
        print()

        # Si la opción seleccionada no es válida, muestra un mensaje de error y continúa con el ciclo.
