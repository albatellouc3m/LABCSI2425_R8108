import os

from flask import Flask, render_template, request, redirect, flash, session, url_for
#from flask_session import Session
import data_management
import sql

app = Flask(__name__)
app.secret_key = os.urandom(24) # Secret key for Flask session
# Configure server-side session
app.config["SESSION_TYPE"] = "filesystem"  # Alternatively, use Redis for production
app.config["SESSION_PERMANENT"] = False  # Set to True if you want permanent sessions
#Session(app)  # Use Flask-Session to store sessions server-side

# TODO; Rotar clave de encripcion. Cada x tiempo desencriptar y volver a encriptar los datos cambiando el salt a la hora de generar la clave
@app.route("/")
def home():
    # Verifica si el usuario está en la sesión
    username = session.get("username", None)  # Devuelve None si no está en la sesión

    # Renderiza la página de inicio, pasando el nombre de usuario si está autenticado
    return render_template("home.html", username=username)


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
            print(f"Slat upon login: {salt}")
            encryption_key, _ = data_management.generar_clave_desde_contraseña(password, salt)
            session["encryption_key"] = encryption_key
            print(f"key upon login: {encryption_key}")

            app.logger.debug("Inicio de sesión exitoso")
            flash("Inicio de sesión exitoso", "success")
            return redirect(url_for("home"))  # Redirigir a la página de inicio
        else:
            app.logger.debug("Fallo al iniciar sesion")
            flash(message, "danger")  # Mostrar un mensaje de error si el login falló
            return redirect(url_for("login"))
    return render_template("login.html")



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

        salt = os.urandom(16)
        print(f"Salt upon register: {salt}")

        # Llamar a la función registrar_usuario de data_management.py
        status, message = data_management.registrar_usuario(username, password, name, surname1, surname2, email, salt)

        if status == 0:
            flash("Registro exitoso", "success")
            app.logger.debug(f"Registro exitoso\nAlgoritmo: AES-CBC | Longitud de clave: {len(data_management.cargar_clave())}")
            return redirect("/login")
        else:
            app.logger.debug(f"Registro fallido {message}")
            flash(message, "danger")
            return redirect("/")
    else:
        # Mostrar el formulario de registro
        return render_template("register.html")

"""@app.route("/register", methods=["POST", "GET"])
def register_user():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        surname1 = request.form['surname1']
        surname2 = request.form['surname2']
        email = request.form['email']

        salt = os.urandom(16)
        print(f"Salt upon register: {salt}")

        # Llamar a la función registrar_usuario de data_management.py
        status, message = data_management.registrar_usuario(username, password, name, surname1, surname2, email, salt)

        if status == 0:
            flash("Registro exitoso", "success")
            app.logger.debug(f"Registro exitoso\nAlgoritmo: AES-CBC | Longitud de clave: {len(data_management.cargar_clave())}")
            return redirect("/login")
        else:
            app.logger.debug(f"Registro fallido {message}")
            flash(message, "danger")
            return redirect("/")
"""

@app.route("/test/<string:name_test>")
def mostrar_test(name_test):
    # Obtener los detalles del test
    test = data_management.obtener_test(name_test)
    if isinstance(test, str):  # Si hubo un error al obtener el test
        flash(test, "danger")
        app.logger.debug(test)
        return redirect("/")

    # Obtener las preguntas del test
    preguntas = data_management.obtener_preguntas(name_test)
    if isinstance(preguntas, str):  # Si hubo un error al obtener las preguntas
        flash(preguntas, "danger")
        app.logger.debug(preguntas)
        return redirect("/")

    # Renderizar la plantilla y pasar los datos
    return render_template("mostrar_test.html", test=test, preguntas=preguntas)


# Ruta para guardar las respuestas del usuario
@app.route("/guardar_respuestas", methods=["POST"])
def guardar_respuestas():
    username = session["username"]  # Recuperar el usuario autenticado de la sesión
    if not username:
        flash("Usuario no autenticado", "danger")
        return redirect("/login")

    name_test = request.form['name_test']
    preguntas = request.form.getlist('question[]')
    respuestas = request.form.getlist('respuestas[]')

    # Llamar a la función en data_management.py que guarda las respuestas y calcula el resultado
    key = session["encryption_key"]
    salt = session["salt"]
    status, message, result, description = data_management.calcular_y_guardar_resultado(username, name_test, preguntas, respuestas, key, salt)

    if status == 0:
        flash(message, "Success")
        app.logger.debug(message)
        return render_template("mostrar_resultado.html", name_test=name_test, result=result, description=description)
    else:
        flash(message, "danger")
        app.logger.debug(f"Fallo al guardar respuestas: {message}")
        return redirect("/")

"""# Ruta opcional para ver las respuestas del usuario a un test
@app.route("/ver_respuestas/<string:name_test>")
def ver_respuestas(name_test):
    username = request.form['username']  # Asumimos que el usuario está autenticado
    respuestas = data_management.obtener_respuestas(name_test, username)

    if isinstance(respuestas, str):  # Si hubo un error
        flash(respuestas, "danger")
        return redirect("/")

    return render_template("ver_respuestas.html", respuestas=respuestas)"""


@app.route("/logout")
def logout():
    session.pop("username", None)  # Eliminar el nombre de usuario de la sesión
    app.logger.debug("Has cerrado sesión exitosamente")
    return redirect(url_for("login"))


@app.route("/perfil")
def perfil():
    if "username" not in session:
        app.logger.debug("Por favor, inicia sesión para continuar")
        return redirect(url_for("login"))

    username = session["username"]
    key = session["encryption_key"]
    print(f"key in profile: {key}")
    resultados = data_management.obtener_resultados_usuario(username, key)
    if isinstance(resultados, str):
        app.logger.debug(resultados)
        return redirect("/")

    amigos = sql.ver_amigos([username])
    if isinstance(amigos, str):
        app.logger.debug(amigos)
        return redirect("/")

    solicitudes = sql.ver_solicitudes([username])

    if isinstance(amigos, str):
        app.logger.debug(amigos)
        return redirect("/")

    return render_template("ver_perfil.html", username=username, resultados=resultados, amigos=amigos, solicitudes=solicitudes)


@app.route("/enviar_solicitud_amigo", methods=["POST"])
def enviar_solicitud_amigo():
    if "username" not in session:
        flash("Por favor, inicia sesión para continuar", "danger")
        return redirect(url_for("login"))

    username = session["username"]
    key = session["encryption_key"]
    key_encriptada = data_management.encriptar_datos_clave_sistema(key)
    friend_username = request.form["friend_username"]

    status, message = data_management.crear_solicitud(username, friend_username, key_encriptada)

    if status == 0:
        flash("Solicitud de amistad enviada exitosamente", "success")
        app.logger.debug("Solicitud de amistad enviada exitosamente")
    else:
        flash(f"No se pudo enviar la solicitud: {message}", "danger")
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
    if isinstance(resultados_amigo, str):
        app.logger.debug(resultados_amigo)
        return redirect("/")
    # print(f"{friend},{resultados_amigo}, {contraseña_amigo_desencriptada}")
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

app.run(debug=True)
