PASOS A SEGUIR PARA PODER ABRIR LA PÁGINA WEB Y QUE VAYA CORRECTAMENTE LA BASE DE DATOS

Estos son los pasos que hay que seguir para poder conectar el archivo a la base de datos:
1. Configurar la base de datos:
    Al ser una base de datos del software de mySQL, se debe tener instalado dicho software.

    1.1 Si todavía no lo tienes instalado, sigue estos pasos para instalarlo:
        1.1.1 Instala el software.
        En linux, puedes poner este comando en la terminal para instalar el software:
                    sudo apt update
                    sudo apt install mysql-server

        1.1.2 Inicia el servidor de MySQL para configurar el usuario root con este comando:
                    sudo systemctl start mysql

        1.1.3. Configura la contraseña del usuario root, cambia 'nueva_contraseña' por una contraseña a tu gusto
                    ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'nueva_contraseña';

        1.1.4 Una vez cambiada la contraseña, sal del servidor de sql para que se mantengan los cambios
                    exit;

    1.2 Tras ya haber configurado MySQL, intentaremos exportar las tablas y las querys de inserción de las preguntas
        1.2.1 Abre la terminal y pon este comando para poder acceder a MySQL, ingresa tu contraseña cuando te lo pida
            mysql -u root -p

        1.2.2 Si todavia no tienes una base de datos creada, puedes crear una para meter todos los datos con este comando:
            CREATE DATABASE LABCSI2425_R8108_db2;

            Si sin embargo ya tienes una base de datos que quieras utilizar para importar todas las tablas de nuestra web pon este comando:
            USE LABCSI2425_R8108_db2

            RECOMENDAMOS QUE SE LLAME LABCSI2425_R8108_db2 ya que a la hora de conectarla va a ser mas facil

        1.2.3 Sal de MySQL para poder insertar las tablas
            exit;

        1.2.3 Una vez elegida la base de datos donde quieras poner las tablas, importa todas las files correspondientes de las tablas
            EN LA TERIMINAL ORIGINAL DE LINUX NO EN MYSQL!!!!!!!!!!!
            /ruta/al/directorio/*.sql -> establece la ruta donde esta la carpeta DESCOMPRIMIDA de las tablas de la base
            de datos que quieras importar. Por ejemplo, si tengo mi carpeta LABCSI2425_R8108_db2.zip descomprimida como
            LABCSI2425_R8108_db2 en descargas puedo poner este comando como ruta: /home/Alba/Descargas/LABCSI2425_R8108_db2/*.sql
            entonces se seleccionaran todos los archivos sql que hay en la carpeta LABCSI2425_R8108_db2 DESCOMPRIMIDA

            POR FAVOR PON LA RUTA COMO ESTA EN TU ORDENADOR QUE SI NO NO FUNCIONA

            recomendamos abrir una terminal nueva en donde tengas el archivo .zip descomprimido y ejecutar este codigo simplemente:
            for file in LABCSI2425_R8108_db2/*.sql; do
                mysql -u root -p LABCSI < "$file"
            done

            si no, puedes abrir una terminal normal y ejecutar este otro codigo CON TU RUTA AL DIRECTORIO DONDE ESTA EL
            FOLDER QUE TIENE TODAS LAS TABLAS Y QUERYS DESCOMPRIMIDAS DE SQL
            for file in /home/alba/Descargas/LABCSI2425_R8108_db2/*.sql; do
                mysql -u root -p LABCSI2425_R8108_db2 < "$file"
            done

            Vas a tener que escribir la contraseña muchas veces hasta que se termine de cargar todas las tablas...


        1.2.4 Verificar si la importación ha sido correcta
            Primero, vuelve a conectarte a MySQL en la terminal
                mysql -u root -p

            Después, conectate a la base de datos donde has cargado todas las tablas antes:
                USE LABCSI2425_R8108_db2

            Y ahi dentro pon los siguientes comandos
                SHOW TABLES;

                Al escribir este comando, se deberia mostrar eso si la importacion ha sido correcta:
                +--------------------------------+
                | Tables_in_LABCSI2425_R8108_db2 |
                +--------------------------------+
                | PosResults                     |
                | Questions                      |
                | Results                        |
                | Test                           |
                | UserAnswers                    |
                | Users                          |
                | friends                        |
                +--------------------------------+
                7 rows in set (0,02 sec)

                SELECT * FROM Tests;
                +---------------------------+--------------------------------------------------------------------------+------------+
                | name_test                 | description                                                              | date       |
                +---------------------------+--------------------------------------------------------------------------+------------+
                | Test de Comida            | Según estas preguntas, descubre que comida pegaría con tu personalidad   | 2024-10-23 |
                | Test de Dedo Pie          | Descubre que dedo del pie serías contestando a estas preguntas           | 2024-10-23 |
                | Test de Electrodomesticos | ¿Qué electrodoméstico eres según estas preguntas interesantes?           | 2024-10-23 |
                | Test de Harry Potter      | ¿Qué casa de Harry Potter eres?                                          | 2024-10-23 |
                | Test de Personalidad      | Descubre más sobre tu personalidad                                       | 2024-10-23 |
                | Test de Sabores de Pizza  | Descubre qué tipo de pizza eres                                          | 2024-10-23 |
                +---------------------------+--------------------------------------------------------------------------+------------+
                6 rows in set (0,00 sec)

                SHOW PROCEDURE STATUS WHERE Db = 'LABCSI2425_R8108_db2';
                +--------+-------------------------+-----------+----------------+---------------------+---------------------+---------------+---------+----------------------+----------------------+--------------------+
                | Db     | Name                    | Type      | Definer        | Modified            | Created             | Security_type | Comment | character_set_client | collation_connection | Database Collation |
                +--------+-------------------------+-----------+----------------+---------------------+---------------------+---------------+---------+----------------------+----------------------+--------------------+
                | LABCSI | calcular_resultado_test | PROCEDURE | root@localhost | 2024-10-29 19:54:38 | 2024-10-29 19:54:38 | DEFINER       |         | utf8mb4              | utf8mb4_0900_ai_ci   | utf8mb4_0900_ai_ci |
                +--------+-------------------------+-----------+----------------+---------------------+---------------------+---------------+---------+----------------------+----------------------+--------------------+
                1 row in set (0,00 sec)


        1.2.5 Si no ha funcionado, puedes instalar MySQL Workbench, e importar las tablas y querys ahi
        Ejecuta este comando para salir del MySQL
            exit;

2 Conexión con python y MySQL
    2.1 Una vez importadas todas las tablas y querys, toca conectar python con MySQL para que la web funcione correctamente.
    Para ello tienes que tener instalada la extensión de mysql-connector-python
    Puedes escribir este codigo en la terminal de python para poder instalarla correctamente:
        pip install mysql-connector-python

    2.2 Ya teniendo la extensión instalada, es hora de conectarlo a MySQL, para ello debes cambiar los datos que hay en
    database_info.txt introduciendo la contraseña que previamente has puesto al configurar MySQL

        user=root
        password=****CAMBIA ESTO****
        host=127.0.0.1
        database=LABCSI2425_R8108_db2 #si tambien has puesto un nombre distinto a la base de datos cambialo aqui


3 Ya estaría configurada la base de datos :)
Ahora solo hace falta ejecutar el codigo en main.py y clickear en el enlace que sale para poder empezar a disfrutar
de la pagina web.

Si ha habido algun error, escribenos que sin base de datos la pagina web no tiene nignun sentido.






