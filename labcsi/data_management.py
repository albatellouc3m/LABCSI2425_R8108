import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sql  # Importar la conexión a la base de datos y el cursor de sql.py
import base64

####REGISTRO Y AUTENTIFICACION######
# Función para registrar usuarios en la base de datos
def registrar_usuario(username, password, name, surname1, surname2, email, salt):
    if username == "":
        return (2, "Username cannot be empty")
    if password == "":
        return (3, "Password cannot be empty")
    if sql.comprobar_existencia_usuario(username):
        return (1, "Username already exists")

    pswd_hash = hash_password(password)

    # No encriptamos el username porque se usa en referencias en la base de datos
    # para encriptar los datos de registro usamos encripcion simetrica con la clave del sistema
    encrypted_name, encrypted_surname1, encrypted_surname2, encrypted_email = encriptar_datos_clave_sistema(name, surname1, surname2, email)

    return sql.insertar_usuario(username, pswd_hash, encrypted_email, encrypted_name, encrypted_surname1, encrypted_surname2, salt)


def hash_password(password):
    # Generar un salt y hashear la contraseña
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


# Función para autenticar usuarios con la base de datos
def autentificar_usuario(username, password):
    sql.cursor.execute("SELECT password FROM Users WHERE username = %s", (username,))
    result = sql.cursor.fetchone()

    if result:
        stored_hash = result[0]
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):  # Convertir el hash recuperado a bytes
            return (0, "Success")
        else:
            return (1, "Incorrect password")
    else:
        return (2, "User not found")


####ENCRIPTACION######
def encriptar_datos_clave_sistema(*args):
    key = cargar_clave()
    f = Fernet(key)

    # Encrypt the data, handles both string and byte inputs (keys namely)
    encrypted_values = tuple(f.encrypt(arg if isinstance(arg, bytes) else arg.encode()).decode() for arg in args)
    # If only one argument was passed, return just the single encrypted value
    if len(encrypted_values) == 1:
        return encrypted_values[0]

    return encrypted_values


# Generar la clave de encriptación y guardarla en un archivo seguro
def generar_clave():
    key = Fernet.generate_key()
    with open("clave.key", "wb") as key_file:
        key_file.write(key)


def cargar_clave():
    return open("clave.key", "rb").read()


# variable is_binary defines whether the data that is encrypted in binary, default entry is binary.
def desencriptar_datos_clave_sistema(*args, is_binary=True):
    key = cargar_clave()
    f = Fernet(key)

    decrypted_values = []

    # Decrypt the data, handles both string and byte inputs (keys namely)
    for arg in args:
        if is_binary:
            decrypted_value = f.decrypt(arg.encode()) # leave output in binary
        else:
            decrypted_value = f.decrypt(arg.encode()).decode()
        decrypted_values.append(decrypted_value)

    # If only one argument was passed, return just the single decrypted value
    if len(decrypted_values) == 1:
        return decrypted_values[0]

    return tuple(decrypted_values)


def generar_clave_desde_contraseña(password, salt=None):
    # Para generar la key para encriptar por primera vez creamos un SALT, cuando vayamos a desencriptar generaremos la clave con el salt con la que se creo
    if salt is None:
        salt = os.urandom(16)  # 16 bytes de salt

    # Función PBKDF2 para derivar la clave
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # Derivar la clave a partir de la contraseña
    key = kdf.derive(password.encode())  # La contraseña debe estar en bytes
    return key, salt

def encriptar_datos_con_clave_derivada(data, key, salt):
    # Crear un nonce aleatorio (12 bytes para GCM)
    nonce = os.urandom(12)

    # Cifrar los datos con AES-GCM
    aesgcm = AESGCM(key)

    # Only encode if data is not already in bytes such as when passing a key as data
    if isinstance(data, bytes):
        data_to_encrypt = data
    else:
        data_to_encrypt = data.encode()

    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, None)

    encrypted_data = base64.b64encode(salt + nonce + ciphertext).decode('utf-8')

    # Retornar el texto cifrado codificado
    return encrypted_data



# variable is_binary defines whether the data that is encripted is binary, default entry is text. I assume the input to this function will be a string as I mostly encript strings.
def desencriptar_datos_con_clave_derivada(encrypted_data, key, is_binary=False):
    encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))

    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    # Descifrar los datos con AES-GCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    if is_binary:
        return plaintext
    return plaintext.decode('utf-8')


def encriptar_respuestas(respuestas, resultado, description, key, salt):
    # Encriptar las respuestas utilizando la clave derivada de la contraseña
    respuestas_encriptadas = [encriptar_datos_con_clave_derivada(respuesta, key, salt) for respuesta in respuestas]

    # Encriptar el resultado
    resultado_encriptado = encriptar_datos_con_clave_derivada(resultado, key, salt)

    # Encriptar la descripcion
    descripcion_encriptada = encriptar_datos_con_clave_derivada(description, key, salt)

    # Devolver las respuestas y el resultado encriptados
    return respuestas_encriptadas, resultado_encriptado, descripcion_encriptada


####MANEJO DE DATOS######
# Función para guardar respuestas y calcular el resultado encriptado
def calcular_y_guardar_resultado(username, name_test, preguntas, respuestas, key, salt):
    # Primero, guardar las respuestas del usuario llamando a guardar_respuestas
    status, message = sql.guardar_respuestas(username, name_test, preguntas, respuestas)
    if status != 0:
        return status, message, None, None

    status, message = sql.calcular_resultado(username, name_test)
    if status != 0:
        # Si algo sale mal borramos de la base de datos los resultados y respuestas del usuario para asegurarnos de que no se quedan guardados en clar
        sql.borrar_ultimas_respuestas(username)
        return status, message, None, None

    status, message, id_resultado, resultado, description = sql.recuperar_resultado(username, name_test)
    if status != 0:
        # Si algo sale mal borramos de la base de datos los resultados y respuestas del usuario para asegurarnos de que no se quedan guardados en clar
        sql.borrar_ultimas_respuestas(username)
        sql.borrar_ultimo_resultado(username)
        return status, message, None, None

    # Encriptar las respuestas y el resultado
    try:
        respuestas_encriptadas, resultado_encriptado, descripcion_encriptada = encriptar_respuestas(respuestas, resultado, description, key, salt)
    except Exception as e:
        # Si algo sale mal borramos de la base de datos los resultados y respuestas del usuario para asegurarnos de que no se quedan guardados en clar
        sql.borrar_ultimas_respuestas(username)
        sql.borrar_ultimo_resultado(username)
        return 1, f"fallo al encriptar respuestas: {e}", None, None

    # Actualizar las respuestas y el resultado encriptadas
    status, message = sql.guardar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas)
    if status != 0:
        # Si algo sale mal borramos de la base de datos los resultados y respuestas del usuario para asegurarnos de que no se quedan guardados en clar
        sql.borrar_ultimas_respuestas(username)
        sql.borrar_ultimo_resultado(username)
        return status, message, None, None

    status, message = sql.guardar_resultado_encriptado(id_resultado, resultado_encriptado, descripcion_encriptada)
    if status != 0:
        # Si algo sale mal borramos de la base de datos los resultados y respuestas del usuario para asegurarnos de que no se quedan guardados en clar
        sql.borrar_ultimas_respuestas(username)
        sql.borrar_ultimo_resultado(username)
        return status, message, None, None

    return 0, f"Respuestas guardadas y resultado calculado correctamente\nAlgoritmo: AES-GCM | Longitud de clave: 32 bytes\nRespuestas Encriptadas: {respuestas_encriptadas}\nResultado Encriptado: {resultado_encriptado}\nDescripcion Encriptada {descripcion_encriptada}", resultado, description



# Obtener los resultados de los tests del usuario
def obtener_resultados_usuario(username, key):
    try:
        resultados_desencriptados = [(r[0],desencriptar_datos_con_clave_derivada(r[1], key),desencriptar_datos_con_clave_derivada(r[2], key),r[3]) for r in sql.recuperar_resultados_usuario(username)]
        return resultados_desencriptados
    except Exception as e:
        return f"Error al obtener los resultados: {str(e)}"


# Obtener las respuestas del usuario para un test específico
def obtener_respuestas_usuario(username, name_test, key):
    try:
        respuestas_desencriptadas = [(r[0],desencriptar_datos_con_clave_derivada(r[1], key)) for r in sql.recuperar_respuestas_usuario(username, name_test)]
        return respuestas_desencriptadas
    except Exception as e:
        return f"Error al obtener las respuestas: {str(e)}"


def crear_solicitud(username, friend_username, key_encriptada):
    status, message = sql.enviar_solicitud(username, friend_username, key_encriptada)
    return status, message


def crear_amistad(username, friend, key, salt):
    friend_key_encriptada = sql.coger_key_solicitante(friend, username)
    friend_key = desencriptar_datos_clave_sistema(friend_key_encriptada)
    friend_salt = sql.obtener_salt_usuario(friend)
    # Encriptamos la clave del que acepta la solicitud (username) con la clave del solicitante (friend)
    username_encripted_key = encriptar_datos_con_clave_derivada(key, friend_key, friend_salt)
    # Encriptamos la clave del solicitante (friend) con la clave del que acepta la solicitud (username)
    friend_encripted_key = encriptar_datos_con_clave_derivada(friend_key, key, salt)
    sql.grabar_amistad(username, friend, username_encripted_key, friend_encripted_key)
