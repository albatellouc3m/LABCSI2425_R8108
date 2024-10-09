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
def insertar_usuario(username, password, email, name, surname1, surname2):
    sql = """
        INSERT INTO Users (username, password, email, name, surname1, surname2, reg_date)
        VALUES (%s, %s, %s, %s, %s, %s, CURDATE())
    """

    values = (username, password, email, name, surname1, surname2)

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