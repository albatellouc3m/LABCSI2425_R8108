from flask import Flask, render_template, request, redirect, flash, session, url_for
import data_management
app = Flask(__name__)
app.secret_key = "caca"

@app.route("/")
def register():
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Supongamos que tienes una función en `data_management.py` que autentifica al usuario
        from data_management import autentificar_usuario

        status, message = autentificar_usuario(username, password)
        if status == 0:  # Si la autenticación fue exitosa
            session["username"] = username  # Almacenar el nombre de usuario en la sesión
            session["password"] = data_management.encriptar_datos_registro(password)
            app.logger.debug("Inicio de sesión exitoso")
            flash("Inicio de sesión exitoso", "success")
            return redirect(url_for("home"))  # Redirigir a la página de inicio
        else:
            app.logger.debug("Fallo al iniciar sesion")
            flash(message, "danger")  # Mostrar un mensaje de error si el login falló
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/home")
def home():
    #data_management.generar_clave()  # Solo debes llamarla UNA VEZ para generar la clave
    #lol.encriptar_posresults()
    if "username" not in session:  # Verifica si el usuario está en la sesión
        flash("Por favor, inicia sesión para continuar", "danger")
        return redirect(url_for("login"))

    # Si el usuario está autenticado
    username = session["username"]
    return render_template("home.html", username=username)


@app.route("/register", methods=["POST"])
def register_user():
    username = request.form['username']
    password = request.form['password']
    name = request.form['name']
    surname1 = request.form['surname1']
    surname2 = request.form['surname2']
    email = request.form['email']

    # Llamar a la función registrar_usuario de data_management.py
    status, message = data_management.registrar_usuario(username, password, name, surname1, surname2, email)

    if status == 0:
        flash("Registro exitoso", "success")
        app.logger.debug(f"Registro exitoso\nAlgoritmo: AES-CBC | Longitud de clave: {len(data_management.cargar_clave())}")
        return redirect("/login")
    else:
        app.logger.debug(f"Registro fallido {message}")
        flash(message, "danger")
        return redirect("/")


@app.route("/test/<string:name_test>")
def mostrar_test(name_test):
    # Obtener los detalles del test
    test = data_management.obtener_test(name_test)
    if isinstance(test, str):  # Si hubo un error al obtener el test
        flash(test, "danger")
        return redirect("/")

    # Obtener las preguntas del test
    preguntas = data_management.obtener_preguntas(name_test)
    if isinstance(preguntas, str):  # Si hubo un error al obtener las preguntas
        flash(preguntas, "danger")
        return redirect("/")

    # Renderizar la plantilla y pasar los datos
    return render_template("mostrar_test.html", test=test, preguntas=preguntas)


# Ruta para guardar las respuestas del usuario
@app.route("/guardar_respuestas", methods=["POST"])
def guardar_respuestas():
    username = session.get('username')  # Recuperar el usuario autenticado de la sesión
    if not username:
        flash("Usuario no autenticado", "danger")
        return redirect("/login")

    name_test = request.form['name_test']
    preguntas = request.form.getlist('question[]')
    respuestas = request.form.getlist('respuestas[]')

    # Llamar a la función en data_management.py que guarda las respuestas y calcula el resultado
    password = data_management.desencriptar_datos_registro(session["password"])
    status, message, result, description = data_management.calcular_y_guardar_resultado(username, name_test, preguntas, respuestas, password)

    if status == 0:
        flash(message, "Success")
        app.logger.debug(message)
        return render_template("mostrar_resultado.html", name_test=name_test, result=result, description=description)
    else:
        flash(message, "danger")
        app.logger.debug(f"Fallo al guardar respuestas: {message}")
        return redirect("/home")

# Ruta opcional para ver las respuestas del usuario a un test
@app.route("/ver_respuestas/<string:name_test>")
def ver_respuestas(name_test):
    username = request.form['username']  # Asumimos que el usuario está autenticado
    respuestas = data_management.obtener_respuestas(name_test, username)

    if isinstance(respuestas, str):  # Si hubo un error
        flash(respuestas, "danger")
        return redirect("/")

    return render_template("ver_respuestas.html", respuestas=respuestas)

@app.route("/logout")
def logout():
    session.pop("username", None)  # Eliminar el nombre de usuario de la sesión
    flash("Has cerrado sesión exitosamente", "success")
    return redirect(url_for("login"))



app.run(debug=True)
