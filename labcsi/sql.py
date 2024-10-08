import mysql.connector

db = mysql.connector.connect(
    user='root',
    password='Alba.2004',
    host='localhost',
    database='LABCSI2425_R8108_db2'
)

cursor = db.cursor()


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
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False


