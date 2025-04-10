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
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()


# Función para insertar un usuario en la base de datos
def insertar_usuario(username, password, email, name, surname1, surname2, salt, encrypted_private_key):
    sql = """
        INSERT INTO users (username, password, email, name, surname1, surname2, salt, private_key, reg_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURDATE())
    """

    values = (username, password, email, name, surname1, surname2, salt, encrypted_private_key)

    try:
        cursor.execute(sql, values)  # Ejecutar la consulta con los valores
        db.commit()  # Confirmar los cambios
        return (0, f"{password}, {email}, {name}, {surname1}, {surname2}, {salt}, {encrypted_private_key}")
    except mysql.connector.Error as err:
        db.rollback()
        return (4, f"Database error: {err}")


def get_stored_hash(username):
    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    return cursor.fetchone()


def obtener_preguntas(name_test):
    try:
        cursor.execute("SELECT question FROM questions WHERE name_test = %s", (name_test,))
        preguntas = cursor.fetchall()
        return preguntas
    except Exception as e:
        return f"Error al obtener las preguntas: {e}"


def obtener_test(name_test):
    try:
        cursor.execute("SELECT name_test, description FROM test WHERE name_test = %s", (name_test,))
        test = cursor.fetchone()
        return test
    except Exception as e:
        return f"Error al obtener el test: {e}"


def obtener_respuestas(name_test, username):
    try:
        cursor.execute(
            "SELECT question, puntuacion FROM useranswers WHERE name_test = %s AND username = %s",
            (name_test, username)
        )
        respuestas = cursor.fetchall()
        return respuestas
    except Exception as e:
        return f"Error al obtener las respuestas: {e}"


# Guardar las respuestas del usuario en la base de datos
def guardar_respuestas(username, name_test, preguntas, respuestas):
    try:
        for pregunta, respuesta in zip(preguntas, respuestas):
            # Insertar cada respuesta del usuario en la tabla UserAnswers
            cursor.execute(
                "INSERT INTO useranswers (username, name_test, question, puntuacion) VALUES (%s, %s, %s, %s)",
                (username, name_test, pregunta, respuesta)
            )
        db.commit()
        return (0, "Respuestas guardadas correctamente")
    except Exception as e:
        db.rollback()
        return (1, f"Error al guardar las respuestas: {e}")


def borrar_ultimas_respuestas(username):
    cursor.execute("""DELETE ua
        FROM useranswers ua
        JOIN (
            SELECT answer_id
            FROM useranswers
            WHERE username = %s
            ORDER BY answer_id DESC
            LIMIT 10
        ) subquery
        ON ua.answer_id = subquery.answer_id;
    """, (username,))
    db.commit()


def calcular_resultado(username, name_test):
    # Calcular el resultado del test usando el procedimiento almacenado
    try:
        cursor.execute("CALL calcular_resultado_test(%s, %s)", (username, name_test))
        db.commit()
        return (0, "Resultado guardado correctamente")
    except Exception as e:
        db.rollback()
        return(2, f"Error al calcular resultado: {e}")


def borrar_ultimo_resultado(username):
    cursor.execute("""
        DELETE FROM results
        WHERE result_id = (
            SELECT result_id
            FROM results
            WHERE username = %s
            ORDER BY result_id DESC
            LIMIT 1
        );
    """, (username,))
    db.commit()


def recuperar_resultado(username, name_test):
    try:
        # Recuperar el resultado calculado de la tabla Results
        cursor.execute(
            "SELECT result_id, result, desc_result  FROM results WHERE username = %s AND name_test = %s ORDER BY result_id DESC LIMIT 1",
            (username, name_test))
        id_resultado, resultado, description = cursor.fetchone()  # Tomar los valores del resultado más reciente
        return 0, "resultados recuperados correctamente", id_resultado, resultado, description
    except Exception as e:
        return 7, "fallo al recuperar resultados", None, None, None


def guardar_respuestas_encriptadas(username, name_test, preguntas, respuestas_encriptadas):
    try:
        # Actualizar las respuestas encriptadas en la base de datos
        for pregunta, respuesta_encriptada in zip(preguntas, respuestas_encriptadas):
            cursor.execute(
                "UPDATE useranswers SET puntuacion = %s WHERE username = %s AND name_test = %s AND question = %s",
                (respuesta_encriptada, username, name_test, pregunta)
            )
        db.commit()  # Confirmar la transacción si todo va bien
        return (0, "Respuestas encriptadas guardadas correctamente")
    except Exception as e:
        db.rollback()  # Revertir en caso de error
        return (3, f"Error al guardar las respuestas encriptadas: {e}")


def guardar_resultado_encriptado_con_firma(id_resultado, resultado_encriptado, descripcion_encriptada, signature):
    try:
        # Actualizar el resultado encriptado
        cursor.execute(
            "UPDATE results SET result = %s, desc_result = %s, signature = %s WHERE result_id = %s",
            (resultado_encriptado, descripcion_encriptada, signature, id_resultado)
        )
        db.commit()
        return (0, "Resultado encriptado guardadas correctamente")
    except Exception as e:
        db.rollback()
        return (5,f"Error al guardar el resultado encriptado: {e}, {len(descripcion_encriptada)}")


# para ver_perfil
def recuperar_resultados_usuario(username):
    cursor.execute("""
        SELECT result_id, name_test, result, desc_result, date_result
        FROM results
        WHERE username = %s
        ORDER BY result_id DESC
    """, (username,))
    return cursor.fetchall()

# Recuperar las respuestas del usuario para un test específico
def recuperar_respuestas_usuario(username, name_test):
    cursor.execute("SELECT question, puntuacion FROM useranswers WHERE username = %s AND name_test = %s", (username, name_test))
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
        return (6, f"Error al enviar solicitud: {str(e)}")


def ver_solicitudes(username):
    try:
        cursor.execute(
            "SELECT username1 FROM friends WHERE username2 = %s AND status = 'solicitado';",
            username
        )
        return cursor.fetchall()
    except Exception as e:
        db.rollback()
        return f"fallo al ver solicitudes: {str(e)}"


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


def coger_key_solicitante(solicitante, solicitado):
    try:
        cursor.execute(
            "SELECT key_user2 FROM friends WHERE username1 = %s AND username2 = %s AND status = 'solicitado';",
            (solicitante, solicitado)
        )
        return cursor.fetchall()[0][0]
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

def obtener_usuarios(username):
    cursor.execute("""
        SELECT username 
        FROM users 
        WHERE username != %s
        AND username NOT IN (
            SELECT username2 
            FROM friends 
            WHERE username1 = %s AND status IN ('aceptado', 'solicitado')
            UNION
            SELECT username1 
            FROM friends 
            WHERE username2 = %s AND status IN ('aceptado', 'solicitado')
        )
    """, (username, username, username))
    return [row[0] for row in cursor.fetchall()]

def obtener_clave_privada(username):
    try:
        cursor.execute("SELECT private_key FROM users WHERE username = %s;", (username,))
        result = cursor.fetchone()
        if not result or not result[0]:
            raise ValueError("Clave privada no encontrada para el usuario")
        return result[0]  # Return the encrypted private key
    except Exception as e:
        return f"fallo al recuperar la clave privada encriptada de la base de datos: {str(e)}"

#VERIFICACION DE FIRMA

def obtener_clave_publica(username):
    cursor.execute("SELECT public_key FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    if result:
        return result[0]  # Clave pública en formato PEM
    else:
        raise ValueError("Clave pública no encontrada para el usuario")

def obtener_firma_resultado(id_resultado):
    cursor.execute("SELECT signature FROM results WHERE result_id = %s", (id_resultado,))
    result = cursor.fetchone()
    if result:
        return result[0]  # Firma en formato bytes
    else:
        raise ValueError("Firma no encontrada para el resultado")

#PKI
def insertar_certificado_usuario(username, cert):
    cursor.execute(
        "UPDATE users SET certificate = %s WHERE username = %s",
        (cert, username)
    )
    db.commit()

def obtener_certificado_usuario(username):
    cursor.execute("SELECT certificate FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    return result[0] if result else None