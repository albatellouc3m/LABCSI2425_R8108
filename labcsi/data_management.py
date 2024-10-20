import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sql  # Importar la conexión a la base de datos y el cursor de sql.py
import base64

# Función para registrar usuarios en la base de datos
def registrar_usuario(username, password, name, surname1, surname2, email):
    if username == "":
        return (2, "Username cannot be empty")
    if password == "":
        return (3, "Password cannot be empty")
    if sql.comprobar_existencia_usuario(username):
        return (1, "Username already exists")

    pswd_hash = hash_password(password)

    # No encriptamos el username porque se usa en referencias en la base de datos
    encrypted_name, encrypted_surname1, encrypted_surname2, encrypted_email = encriptar_datos_registro(name, surname1, surname2, email)

    return sql.insertar_usuario(username, pswd_hash, encrypted_email, encrypted_name, encrypted_surname1, encrypted_surname2)


# Función para autenticar usuarios con la base de datos
def autentificar_usuario(username, password):
    sql.cursor.execute("SELECT password FROM Users WHERE username = %s", (username,))
    result = sql.cursor.fetchone()

    if result:
        stored_hash = result[0]  # Asegúrate de que el hash se obtiene correctamente
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):  # Convertir el hash recuperado a bytes
            return (0, "Success")
        else:
            return (1, "Incorrect password")
    else:
        return (2, "User not found")



# Función para guardar resultados de los tests en la base de datos
def save_test_result(username, test_name, answers):
    sql.cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
    result = sql.cursor.fetchone()

    if not result:
        return (1, "User not found")

    # Convertir las respuestas en una cadena (puedes usar JSON si es complejo)
    answers_str = str(answers)

    # Guardar los resultados del test en la base de datos
    try:
        sql.cursor.execute(
            "INSERT INTO TestResults (username, test_name, answers) VALUES (%s, %s, %s)",
            (username, test_name, answers_str)
        )
        sql.db.commit()
        return (0, "Test results saved")
    except Exception as e:
        sql.db.rollback()
        return (2, f"Database error: {e}")

# Función para cargar los resultados de los tests
def load_test_results(username):
    sql.cursor.execute("SELECT test_name, answers FROM TestResults WHERE username = %s", (username,))
    results = sql.cursor.fetchall()

    if results:
        return results
    else:
        return (1, "No results found for this user")


# Obtener las preguntas de un test predeterminado
def obtener_preguntas(name_test):
    try:
        sql.cursor.execute("SELECT question FROM Questions WHERE name_test = %s", (name_test,))
        preguntas = sql.cursor.fetchall()
        return preguntas
    except Exception as e:
        return f"Error al obtener las preguntas: {e}"

# Obtener la información del test
def obtener_test(name_test):
    try:
        sql.cursor.execute("SELECT name_test, description FROM Test WHERE name_test = %s", (name_test,))
        test = sql.cursor.fetchone()
        return test
    except Exception as e:
        return f"Error al obtener el test: {e}"


# Obtener respuestas del usuario para un test específico
def obtener_respuestas(name_test, username):
    try:
        sql.cursor.execute(
            "SELECT question, puntuacion FROM UserAnswers WHERE name_test = %s AND username = %s",
            (name_test, username)
        )
        respuestas = sql.cursor.fetchall()
        return respuestas
    except Exception as e:
        return f"Error al obtener las respuestas: {e}"


# logica para encriptar las respuestas y los resultados

# Generar la clave de encriptación y guardarla en un archivo seguro
def generar_clave():
    key = Fernet.generate_key()
    with open("clave.key", "wb") as key_file:
        key_file.write(key)

def cargar_clave():
    return open("clave.key", "rb").read()

def hash_password(password):
    # Generar un salt y hashear la contraseña
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# TODO: Mover a otra carpeta las cosas de encriptar y tal?
####ENCRIPTAR COSAS######
def encriptar_datos_registro(*args):
    key = cargar_clave()
    f = Fernet(key)

    encrypted_values = tuple(f.encrypt(arg.encode()).decode() for arg in args)
    # If only one argument was passed, return just the single encrypted value
    if len(encrypted_values) == 1:
        return encrypted_values[0]

    return encrypted_values

def desencriptar_datos_registro(*args):
    key = cargar_clave()
    f = Fernet(key)

    decrypted_values = tuple(f.decrypt(arg.encode()).decode() for arg in args)
    # If only one argument was passed, return just the single decrypted value
    if len(decrypted_values) == 1:
        return decrypted_values[0]

    return decrypted_values

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

def encriptar_datos_con_clave_derivada(data, password):
    key, salt = generar_clave_desde_contraseña(password)

    # Crear un nonce aleatorio (12 bytes para GCM)
    nonce = os.urandom(12)

    # Cifrar los datos con AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data.encode(), None)

    # Codificar el ciphertext como Base64
    encrypted_data = base64.b64encode(salt + nonce + ciphertext).decode('utf-8')

    # Retornar el texto cifrado codificado
    return encrypted_data

def desencriptar_datos_con_clave_derivada(encrypted_data, password):
    encrypted_data = base64.b64decode(encrypted_data)

    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]

    # Generar la clave nuevamente a partir de la contraseña y el salt
    key, _ = generar_clave_desde_contraseña(password, salt)

    # Descifrar los datos con AES-GCM
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()

def encriptar_respuestas(respuestas, resultado, description, password):
    # Encriptar las respuestas utilizando la clave derivada de la contraseña
    respuestas_encriptadas = [encriptar_datos_con_clave_derivada(respuesta, password) for respuesta in respuestas]

    # Encriptar el resultado
    resultado_encriptado = encriptar_datos_con_clave_derivada(resultado, password)

    # Encriptar la descripcion
    descripcion_encriptada = encriptar_datos_con_clave_derivada(description, password)

    # Devolver las respuestas y el resultado encriptados
    return respuestas_encriptadas, resultado_encriptado, descripcion_encriptada


# Función para guardar respuestas y calcular el resultado encriptado
def calcular_y_guardar_resultado(username, name_test, preguntas, respuestas, password):
    # Primero, guardar las respuestas del usuario llamando a guardar_respuestas
    status, message = sql.guardar_respuestas(username, name_test, preguntas, respuestas)
    if status != 0:
        return status, message, None, None

    # Si las respuestas se guardaron correctamente
    sql.calcular_resultado(username, name_test)

    id_resultado, resultado, description = sql.recuperar_resultado(username, name_test)

    # Encriptar las respuestas y el resultado
    respuestas_encriptadas, resultado_encriptado, descripcion_encriptada = encriptar_respuestas(respuestas, resultado, description, password)

    # Actualizar las respuestas y el resultado encriptadas
    status, message = sql.guardar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas)
    if status != 0:
        return status, message, None, None
    status, message = sql.guardar_resultado_encriptado(id_resultado, resultado_encriptado, descripcion_encriptada)
    if status != 0:
        return status, message, None, None

    return 0, "Respuestas guardadas y resultado calculado correctamente\nAlgoritmo: AES-GCM | Longitud de clave: 32 bytes", resultado, description



# Obtener los resultados de los tests del usuario
def obtener_resultados_usuario(username, password):
    try:
        resultados_desencriptados = [(r[0],desencriptar_datos_con_clave_derivada(r[1], password),desencriptar_datos_con_clave_derivada(r[2], password),r[3]) for r in sql.recuperar_resultados_usuario(username)]
        return resultados_desencriptados
    except Exception as e:
        return f"Error al obtener los resultados: {str(e)}"


# Obtener las respuestas del usuario para un test específico
def obtener_respuestas_usuario(username, name_test, password):
    try:
        respuestas_desencriptadas = [(r[0],desencriptar_datos_con_clave_derivada(r[1], password)) for r in sql.recuperar_respuestas_usuario(username, name_test)]
        return respuestas_desencriptadas
    except Exception as e:
        return f"Error al obtener las respuestas: {str(e)}"


def crear_solicitud(username, friend_username, password):
    password_encriptada = encriptar_datos_registro(password)
    status, message = sql.enviar_solicitud(username, friend_username, password_encriptada)
    return status, message


def crear_amistad(username, friend, password):
    contraseña_solicitante = sql.coger_contraseña_solicitante(friend, username)
    print(f"contraseña solicitante: {contraseña_solicitante}")
    friend_pass = desencriptar_datos_registro(contraseña_solicitante)
    username_encripted_pass = encriptar_datos_con_clave_derivada(password, friend_pass)
    friend_encripted_pass = encriptar_datos_con_clave_derivada(friend_pass, password)
    sql.grabar_amistad(username, friend, username_encripted_pass, friend_encripted_pass)





















