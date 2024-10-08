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
        return (4, f"Database error: {err}")


