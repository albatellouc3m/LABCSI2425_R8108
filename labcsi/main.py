import os

from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_session import Session


import data_management
import sql


app = Flask(__name__)
app.secret_key = os.urandom(24) # Clave secreta para la session
# Configuracion de la session almacenada en el servidor
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)  # Usamos Flask-Session para guardar la session en el lado del servidor

# TODO: mejoras: Captura de excepciones (de forma sistemática y con su listado de excepciones) ya tenemos app.loger.debug, solamente hay que llamar a algo que de un listado de excepciones al finalizar
@app.route("/")
def home():
    # Verifica si el usuario está en la sesión
    username = session.get("username", None)  # Devuelve None si no está en la sesión

    # Renderiza la página de inicio, pasando el nombre de usuario si está autenticado
    return render_template("home.html", username=username)


@app.route("/register", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        # Procesar el formulario de registro
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        surname1 = request.form['surname1']
        surname2 = request.form['surname2']
        email = request.form['email']

        # El salt que usa cada usuario para generar su clave se mantendra constante haciendo así que su clave sea siempre la misma. Esto resulta util para poder compartirla con sus amigos.
        salt = os.urandom(16)
        encryption_key, _ = data_management.generar_clave_desde_contraseña(password, salt)

        # Generar par de claves usadas en el proceso de firma
        private_key, public_key = data_management.generate_user_keys(username, encryption_key)

        print(f"DEBUG: private_key_pem: {private_key.decode()}")

        print(f"DEBUG: username={username}, type={type(username)}")
        print(f"DEBUG: encryption_key={encryption_key}, type={type(encryption_key)}")

        # Crear CSR
        solicitudes_dir = os.path.join(os.environ["AC_DIR"], "solicitudes")

        data_management.generate_and_save_csr(private_key, username, solicitudes_dir)
        app.logger.debug(f"CSR guardado para {username}")

        # Llamar a la función registrar_usuario de data_management.py encargada de hashear la contraseña, encriptar los datos relevantes y guardarlos en la base de datos
        # La clave privada sera encriptada con la clave derivada de la contraseña del usuario
        # La clave publica, almacenada dentro del certificado, sera añadida a la base de datos cuando la AC haya aprobado su certificado. De momento el campo del certificado en la tabla users de la base de datos sera null.
        status, message = data_management.registrar_usuario(username, password, name, surname1, surname2, email, salt, private_key, encryption_key)

        if status == 0:
            app.logger.debug(f"Registro exitoso\nAlgoritmo: AES-CBC | Longitud de clave: {len(data_management.cargar_clave())}")
            app.logger.debug(message)
            return redirect("/login")
        else:
            app.logger.debug(f"Registro fallido {message}")
            return redirect("/register")
    else:
        # Mostrar el formulario de registro
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        status, message = data_management.autentificar_usuario(username, password)
        if status == 0:  # Si la autenticación fue exitosa
            session["username"] = username
            salt = sql.obtener_salt_usuario(username)
            session["salt"] = salt
            encryption_key, _ = data_management.generar_clave_desde_contraseña(password, salt)
            session["encryption_key"] = encryption_key

            app.logger.debug("Inicio de sesión exitoso")
            return redirect(url_for("home"))  # Redirigir a la página de inicio
        else:
            app.logger.debug("Fallo al iniciar sesion") # Mostrar un mensaje de error si el login falló
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/test/<string:name_test>")
def mostrar_test(name_test):
    # Obtener los detalles del test
    test = sql.obtener_test(name_test)
    if isinstance(test, str):  # Si hubo un error al obtener el test
        app.logger.debug(test)
        return redirect("/")

    # Obtener las preguntas del test
    preguntas = sql.obtener_preguntas(name_test)
    if isinstance(preguntas, str):  # Si hubo un error al obtener las preguntas
        app.logger.debug(preguntas)
        return redirect("/")

    # Renderizar la plantilla y pasar los datos
    return render_template("mostrar_test.html", test=test, preguntas=preguntas)


# Ruta para guardar las respuestas del usuario
@app.route("/guardar_respuestas", methods=["POST"])
def guardar_respuestas():
    username = session["username"]  # Recuperar el usuario autenticado de la sesión
    if not username:
        app.logger.debug("Usuario no autenticado")
        return redirect("/login")

    name_test = request.form['name_test']
    preguntas = request.form.getlist('question[]')
    respuestas = request.form.getlist('respuestas[]')

    # Llamar a la función en data_management.py que guarda las respuestas y calcula el resultado
    encryption_key = session["encryption_key"]
    salt = session["salt"]
    status, message, result, description = data_management.calcular_y_guardar_resultado(username, name_test, preguntas, respuestas, encryption_key, salt)

    if status == 0:
        app.logger.debug(message)
        return render_template("mostrar_resultado.html", name_test=name_test, result=result, description=description)
    else:
        app.logger.debug(f"Fallo al guardar respuestas: {message}")
        return redirect("/")

@app.route("/logout")
def logout():
    session.pop("username", None)  # Eliminar el nombre de usuario de la sesión
    session.pop("encryption_key", None)
    session.pop("salt", None)
    app.logger.debug("Has cerrado sesión exitosamente")
    return redirect(url_for("home"))



@app.route("/perfil")
def perfil():
    if "username" not in session:
        app.logger.debug("Por favor, inicia sesión para continuar")
        return redirect(url_for("login"))

    username = session["username"]
    key = session["encryption_key"]

    # Recuperar resultados del usuario
    resultados = data_management.obtener_resultados_usuario(username, key)
    if isinstance(resultados, str):
        app.logger.debug(resultados)
        return redirect("/")

    # Cargar el certificado de AC y del usuario
    # El certificado del usuario sera emitido por la AC en caso de no existir
    code, mensaje, user_cert_pem, ca_cert_pem = data_management.cargar_certificado(username)
    app.logger.debug(mensaje)
    if code == 1:
        return redirect("/")

    # Verificar si el usuario ya tiene un certificado o hay que emitirlo
    if not user_cert_pem: # Emitir el certificado
        app.logger.debug("El usuario no cuenta con un certificado")
        code, mensaje, user_cert_pem = data_management.emitir_certificado(username)
        if code == 1:
            app.logger.error(mensaje)
            return redirect("/")
        app.logger.debug(mensaje)


    # Verificar la firma de cada resultado
    for resultado in resultados:
        name_test, result, description, date_result, result_id = resultado
        data_to_sign = f"{result}:{description}"

        signature = sql.obtener_firma_resultado(result_id)

        es_valida = data_management.verificar_firma(user_cert_pem, ca_cert_pem, data_to_sign, signature)
        if not es_valida:
            app.logger.debug(f"Firma NO válida para el test {name_test}")
            return redirect("/login")  # Opcional: Manejo de firmas inválidas

    app.logger.debug("Todas las firmas del usuario son válidas")

    # Recuperar amigos y solicitudes
    amigos = sql.ver_amigos([username])
    if isinstance(amigos, str):
        app.logger.debug(amigos)
        return redirect("/")

    solicitudes = sql.ver_solicitudes([username])
    if isinstance(solicitudes, str):
        app.logger.debug(solicitudes)
        return redirect("/")

    return render_template("ver_perfil.html", username=username, resultados=resultados, amigos=amigos, solicitudes=solicitudes)


@app.route("/enviar_solicitud_amigo", methods=["POST"])
def enviar_solicitud_amigo():
    if "username" not in session:
        app.logger.debug("Por favor, inicia sesión para continuar")
        return redirect(url_for("login"))

    username = session["username"]
    key = session["encryption_key"]
    # La llave del solicitante se guarda encriptada con la clave del sistema para que cuando se acepte la solicitud se desencripte y se vuelva a encriptar con la clave del receptor de la solicitud
    key_encriptada = data_management.encriptar_datos_clave_sistema(key)
    friend_username = request.form["friend_username"]

    status, message = data_management.crear_solicitud(username, friend_username, key_encriptada)

    if status == 0:
        app.logger.debug("Solicitud de amistad enviada exitosamente")
    else:
        app.logger.debug(f"No se pudo enviar la solicitud: {message}")

    return redirect(url_for("perfil"))


@app.route("/perfil/añadir_amigo/<string:friend>")
def añadir_amigo(friend):
    username = session["username"]
    key = session["encryption_key"]
    salt = session["salt"]
    data_management.crear_amistad(username, friend, key, salt)
    return redirect(url_for("perfil"))

@app.route("/perfil/borrar_amigo/<string:friend>")
def borrar_amigo(friend):
    username = session["username"]
    sql.borrar_amistad(username, friend)
    return redirect(url_for("perfil"))


@app.route("/ver_perfil_amigo/<string:friend>", methods=["GET"])
def ver_perfil_amigo(friend):
    username = session["username"]
    key = session["encryption_key"]

    key_amigo_encriptada = sql.coger_key_amigo(username, friend)
    key_amigo_desencriptada = data_management.desencriptar_datos_con_clave_derivada(key_amigo_encriptada, key, True)
    resultados_amigo = data_management.obtener_resultados_usuario(friend, key_amigo_desencriptada)

    # Cargar el certificado de AC
    try:
        with open("./Certificacion/AC/ac1cert.pem", "r") as ca_cert_file:
            ca_cert_pem = ca_cert_file.read()
    except FileNotFoundError:
        app.logger.error("El certificado de la AC no se encontró.")
        return redirect("/")

    # Verificar si el amigo ya tiene un certificado
    friend_cert_pem = sql.obtener_certificado_usuario(friend)

    # Verificar la firma de cada resultado del amigo
    for resultado in resultados_amigo:
        name_test, result, description, date_result, result_id = resultado
        data_to_sign = f"{result}:{description}"
        signature = sql.obtener_firma_resultado(result_id)

        es_valida = data_management.verificar_firma(friend_cert_pem, ca_cert_pem, data_to_sign, signature)
        if not es_valida:
            app.logger.debug(f"Firma NO válida para el test {name_test} del amigo {friend}")
            return redirect("/")  # Opcional: Manejo de firmas inválidas

    app.logger.debug("Todas las firmas del amigo son válidas")

    if isinstance(resultados_amigo, str):
        app.logger.debug(resultados_amigo)
        return redirect("/")
    return render_template("ver_resultados_amigo.html", username=friend, resultados=resultados_amigo, contraseña_amigo=key_amigo_desencriptada)


@app.route("/ver_respuestas/<string:name_test>")
def ver_respuestas_usuario(name_test):
    if "username" not in session:
        app.logger.debug("Por favor, inicia sesión para continuar")
        return redirect(url_for("login"))

    username = session["username"]  # Usamos el nombre de usuario de la sesión, en lugar de request.form
    key = session["encryption_key"]
    respuestas = data_management.obtener_respuestas_usuario(username, name_test, key)
    if isinstance(respuestas, str):
        app.logger.debug(respuestas)
        return redirect("/perfil")

    return render_template("ver_respuestas.html", name_test=name_test, respuestas=respuestas)


@app.route('/obtener_usuarios', methods=['GET'])
def obtener_usuarios():
    if 'username' not in session:
        return jsonify({"error": "Usuario no autenticado"}), 403

    try:
        usuarios = sql.obtener_usuarios(session['username'])
        app.logger.debug(f"Usuarios encontrados: {usuarios}")  # Para verificar los datos en la consola
        return jsonify({"usuarios": usuarios})
    except Exception as e:
        app.logger.debug(f"Error en la consulta: {e}")
        return jsonify({"error": "Error en la base de datos"}), 500


@app.route('/delete_result', methods=['POST'])
def delete_result():
    if 'username' not in session:
        return jsonify({"error": "Usuario no autenticado"}), 403

    username = session['username']
    test_name = request.form['name_test']

    # Eliminar las respuestas y el resultado del test
    try:
        # Primero eliminar las respuestas del usuario para el test
        sql.cursor.execute("DELETE FROM useranswers WHERE username = %s AND name_test = %s", (username, test_name))

        # Luego eliminar el resultado del test
        sql.cursor.execute("DELETE FROM results WHERE username = %s AND name_test = %s", (username, test_name))

        sql.db.commit()  # Confirmar los cambios
        app.logger.debug("Resultado y respuestas del test eliminados correctamente", "success")
    except Exception as e:
        sql.db.rollback()  # Revertir los cambios si hay un error
        app.logger.debug(f"Error al eliminar el resultado y las respuestas: {e}", "danger")

    return redirect(url_for('perfil'))

app.run(debug=True)

