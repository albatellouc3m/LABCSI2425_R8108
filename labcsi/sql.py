import mysql.connector

# Load database configuration from text file
db_config = {}
with open('database_info.txt', 'r') as file:
    for line in file:
        key, value = line.strip().split('=')
        db_config[key] = value

db = mysql.connector.connect(
    user=db_config['user'],
    password=db_config['password'],
    host=db_config['host'],
    database=db_config['database']
)

cursor = db.cursor()


def comprobar_existencia_usuario(username):
    # Verificar si el usuario ya existe
    cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
    return cursor.fetchone()


# Función para insertar un usuario en la base de datos
def insertar_usuario(username, password, email, name, surname1, surname2, salt):
    sql = """
        INSERT INTO Users (username, password, email, name, surname1, surname2, salt, reg_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s, CURDATE())
    """

    values = (username, password, email, name, surname1, surname2, salt)

    try:
        cursor.execute(sql, values)  # Ejecutar la consulta con los valores
        db.commit()  # Confirmar los cambios
        return (0, "Success")
    except mysql.connector.Error as err:
        db.rollback()
        return (4, f"Database error: {err}, {len(email)}")


# Guardar las respuestas del usuario en la base de datos
def guardar_respuestas(username, name_test, preguntas, respuestas):
    try:
        for pregunta, respuesta in zip(preguntas, respuestas):
            # Insertar cada respuesta del usuario en la tabla UserAnswers
            cursor.execute(
                "INSERT INTO UserAnswers (username, name_test, question, puntuacion) VALUES (%s, %s, %s, %s)",
                (username, name_test, pregunta, respuesta)
            )
        db.commit()
        return (0, "Respuestas guardadas correctamente")
    except Exception as e:
        db.rollback()
        return (1, f"Error al guardar las respuestas: {e}")


def calcular_resultado(username, name_test):
    # Calcular el resultado del test usando el procedimiento almacenado
    cursor.execute("CALL calcular_resultado_test(%s, %s)", (username, name_test))
    db.commit()


def recuperar_resultado(username, name_test):
    # Recuperar el resultado calculado de la tabla Results
    cursor.execute(
        "SELECT result_id, result, desc_result  FROM Results WHERE username = %s AND name_test = %s ORDER BY date_result DESC LIMIT 1",
        (username, name_test))
    id_resultado, resultado, description = cursor.fetchone()  # Tomar los valores del resultado más reciente
    return id_resultado, resultado, description


def guardar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas):
    try:
        # Actualizar las respuestas encriptadas en la base de datos
        for pregunta, respuesta_encriptada in zip(preguntas, respuestas_encriptadas):
            cursor.execute(
                "UPDATE UserAnswers SET puntuacion = %s WHERE username = %s AND name_test = %s AND question = %s",
                (respuesta_encriptada, username, name_test, pregunta)
            )
        db.commit()  # Confirmar la transacción si todo va bien
        return (0, "Respuestas encriptadas guardadas correctamente")
    except Exception as e:
        db.rollback()  # Revertir en caso de error
        return (1, f"Error al guardar las respuestas encriptadas: {e}")


def guardar_resultado_encriptado(id_resultado, resultado_encriptado, descripcion_encriptada):
    try:
        # Actualizar el resultado encriptado
        cursor.execute(
            "UPDATE Results SET result = %s, desc_result = %s WHERE result_id = %s",
            (resultado_encriptado, descripcion_encriptada, id_resultado)
        )
        db.commit()
        return (0, "Resultado encriptado guardadas correctamente")
    except Exception as e:
        db.rollback()
        return (1,f"Error al guardar el resultado encriptado: {e}, {len(descripcion_encriptada)}")


# para ver_perfil
def recuperar_resultados_usuario(username):
    cursor.execute("SELECT name_test, result, desc_result, date_result FROM Results WHERE username = %s ORDER BY date_result DESC", (username,))
    return cursor.fetchall()

# Recuperar las respuestas del usuario para un test específico
def recuperar_respuestas_usuario(username, name_test):
    cursor.execute("SELECT question, puntuacion FROM UserAnswers WHERE username = %s AND name_test = %s", (username, name_test))
    return cursor.fetchall()


def ver_amigos(username):
    try:
        cursor.execute(
            "SELECT username2 FROM friends WHERE username1 = %s AND status = 'aceptado';",
            username
        )
        return cursor.fetchall()
    except Exception as e:
        db.rollback()
        return f"fallo al ver amistades: {str(e)}"


def grabar_amistad(username1, username2, key_user1, key_user2):
    cursor.execute(
        "DELETE FROM friends WHERE (username1 = %s AND username2 = %s) OR (username1 = %s AND username2 = %s);",
        (username1, username2, username2, username1)
    )
    cursor.execute(
        "INSERT INTO friends (username1, username2, status, key_user2) VALUES (%s, %s, 'aceptado', %s), (%s, %s, 'aceptado', %s);",
        (username1, username2, key_user2, username2, username1, key_user1)
    )
    db.commit()


def borrar_amistad(username1, username2):
    cursor.execute(
        "DELETE FROM friends WHERE (username1 = %s AND username2 = %s) OR (username1 = %s AND username2 = %s);",
        (username1, username2, username2, username1)
    )
    db.commit()


def enviar_solicitud(petidor, receptor, key_petidor):
    try:
        # Insert a pending friend request
        cursor.execute(
            "INSERT INTO friends (username1, username2, status, key_user2) VALUES (%s, %s, 'solicitado', %s);",
            (petidor, receptor, key_petidor)
        )
        db.commit()
        return (0, "Solicitud enviada")
    except Exception as e:
        db.rollback()
        return (1, f"Error al enviar solicitud: {str(e)}")


def ver_solicitudes(username):
    try:
        cursor.execute(
            "SELECT username1 FROM friends WHERE username2 = %s AND status = 'solicitado';",
            username
        )
        return cursor.fetchall()
    except Exception as e:
        db.rollback()
        return f"fallo al ver amistades: {str(e)}"


def coger_key_solicitante(solicitante, solicitado):
    try:
        cursor.execute(
            "SELECT key_user2 FROM friends WHERE username1 = %s AND username2 = %s AND status = 'solicitado';",
            (solicitante, solicitado)
        )
        return cursor.fetchall()[0][0]
        # key_string = cursor.fetchall()[0][0]
        # print(key_string)
        # key_binary = base64.b64decode(key_string + '=' * (-len(key_string) % 4))
        # return key_binary
    except Exception as e:
        db.rollback()
        return f"fallo al ver amistades: {str(e)}"

def coger_key_amigo(usuario, amigo):
    try:
        cursor.execute(
            "SELECT key_user2 FROM friends WHERE username1 = %s AND username2 = %s AND status = 'aceptado';",
            (usuario, amigo)
        )
        return cursor.fetchone()[0]
    except Exception as e:
        db.rollback()
        return f"fallo al ver amistades: {str(e)}"


def obtener_salt_usuario(username):
    cursor.execute("SELECT salt FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    return result[0]