import bcrypt
from cryptography.fernet import Fernet
import sql  # Importar la conexión a la base de datos y el cursor de sql.py


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
    encrypted_name, encrypted_surname1, encrypted_surname2, encrypted_email = encriptar_datos(name, surname1, surname2, email)

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


# Guardar las respuestas del usuario en la base de datos
def guardar_respuestas(username, name_test, preguntas, respuestas):
    try:
        for pregunta, respuesta in zip(preguntas, respuestas):
            # Insertar cada respuesta del usuario en la tabla UserAnswers
            sql.cursor.execute(
                "INSERT INTO UserAnswers (username, name_test, question, puntuacion) VALUES (%s, %s, %s, %s)",
                (username, name_test, pregunta, respuesta)
            )
        sql.db.commit()
        return (0, "Respuestas guardadas correctamente")
    except Exception as e:
        sql.db.rollback()
        return (1, f"Error al guardar las respuestas: {e}")


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
def encriptar_datos(*args):
    key = cargar_clave()
    f = Fernet(key)

    encrypted_values = tuple(f.encrypt(arg.encode()).decode() for arg in args)
    return encrypted_values

def decriptar_datos(*args):
    key = cargar_clave()
    f = Fernet(key)

    decrypted_values = tuple(f.decrypt(arg.encode()).decode() for arg in args)
    return decrypted_values

def encriptar_respuestas(respuestas, resultado):
    # Cargar la clave de encriptación
    key = cargar_clave()
    f = Fernet(key)

    # Encriptar las respuestas (suponemos que respuestas es una lista de strings)
    respuestas_encriptadas = [f.encrypt(respuesta.encode()).decode() for respuesta in respuestas]

    # Encriptar el resultado
    resultado_encriptado = f.encrypt(resultado.encode()).decode()

    # Devolver las respuestas y el resultado encriptados
    return respuestas_encriptadas, resultado_encriptado

# Función para guardar respuestas y calcular el resultado encriptado
def calcular_y_guardar_resultado(username, name_test, preguntas, respuestas):
    # Primero, guardar las respuestas del usuario llamando a guardar_respuestas
    status, message = guardar_respuestas(username, name_test, preguntas, respuestas)

    if status == 0:  # Si las respuestas se guardaron correctamente
        try:
            # Calcular el resultado del test usando el procedimiento almacenado
            sql.cursor.execute("CALL calcular_resultado_test(%s, %s)", (username, name_test))
            sql.db.commit()

            # Recuperar el resultado calculado de la tabla Results
            sql.cursor.execute(
                "SELECT result, desc_result FROM Results WHERE username = %s AND name_test = %s ORDER BY date_result DESC LIMIT 1", (username, name_test))
            resultado, description = sql.cursor.fetchone()  # Tomar los valores del resultado más reciente


            # Encriptar las respuestas y el resultado
            respuestas_encriptadas, resultado_encriptado = encriptar_respuestas(respuestas, resultado)

            # Actualizar las respuestas y el resultado encriptadas
            actualizar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas)
            #actualizar_resultado_encriptado(username, name_test, resultado_encriptado) #nofunciona

            key = cargar_clave()
            f = Fernet(key)

            resultado_encriptado = f.decrypt(resultado_encriptado.encode()).decode()

            return (0, "Respuestas guardadas y resultado calculado correctamente", resultado_encriptado, description)
        except Exception as e:
            sql.db.rollback()  # Revertir en caso de error durante el cálculo del resultado
            return (1, f"Error al calcular el resultado: {e}", None, None)
    else:
        return (1, message, None, None)  # Retornar el error si no se pudieron guardar las respuestas

def actualizar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas):
    try:
        # Actualizar las respuestas encriptadas en la base de datos
        for pregunta, respuesta_encriptada in zip(preguntas, respuestas_encriptadas):
            sql.cursor.execute(
                "UPDATE UserAnswers SET puntuacion = %s WHERE username = %s AND name_test = %s AND question = %s",
                (respuesta_encriptada, username, name_test, pregunta)
            )
        sql.db.commit()  # Confirmar la transacción si todo va bien
    except Exception as e:
        sql.db.rollback()  # Revertir en caso de error
        print(f"Error al actualizar las respuestas encriptadas: {e}")

def actualizar_resultado_encriptado(username, name_test, resultado_encriptado):
    try:
        # Verificar si hay filas que coincidan con username y name_test
        sql.cursor.execute("SELECT COUNT(*) FROM Results WHERE username = %s AND name_test = %s", (username, name_test))
        count = sql.cursor.fetchone()[0]

        if count == 0:
            print(f"No se encontró ningún resultado para username: {username} y name_test: {name_test}")
            return

        # Actualizar el resultado encriptado si hay coincidencias
        sql.cursor.execute(
            "UPDATE Results SET result = %s WHERE username = %s AND name_test = %s",
            (resultado_encriptado, username, name_test)
        )
        sql.db.commit()
        print(f"Resultado encriptado actualizado correctamente para username: {username} y name_test: {name_test}")
    except Exception as e:
        sql.db.rollback()
        print(f"Error al actualizar el resultado encriptado: {e}")
