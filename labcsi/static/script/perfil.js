
var side_menu = document.getElementById("menu_side");
var btn_open = document.getElementById("btn_open");
var body = document.getElementById("body");
var volver_btn = document.querySelector(".volver-btn");

// Función para ocultar y mostrar el menú
function open_close_menu(){
    body.classList.toggle("body_move");
    side_menu.classList.toggle("menu__side_move");

    // Mostrar el botón "Volver al Inicio" cuando el menú esté desplegado
    if (side_menu.classList.contains("menu__side_move")) {
        volver_btn.style.display = "block"; // Mostrar el botón
    } else {
        volver_btn.style.display = "none";  // Ocultar el botón
    }
}

// Añade el evento al botón de abrir/cerrar menú
btn_open.addEventListener("click", open_close_menu);

$(document).ready(function() {
    let listaVisible = false; // Variable para controlar el estado de visibilidad de la lista

    // Mostrar o cerrar lista de amigos al hacer clic en "TODOS TUS AMIGOS/AS"
    $('#mostrar_amigos').on('click', function() {
        if (listaVisible) {
            // Si la lista está visible, la ocultamos
            $('.amigos-lista').empty();  // Limpiar la lista
        } else {
            // Si la lista no está visible, la mostramos
            let listaAmigos = '';
            if (amigos.length > 0) {
                amigos.forEach(function(amigo) {
                    let borrarAmigoUrl = borrarAmigoUrlBase + amigo[0];  // Concatenar el username del amigo
                    listaAmigos += `<li><a class="amigo-perfil" href="/ver_perfil_amigo/${amigo[0]}"><strong>${amigo[0]}</strong></a> <a href="#" class="borrar-amigo" data-url="${borrarAmigoUrl}">
                    <img src="${cerrarIconUrl}" alt="Cerrar" class="cerrarbtn">
                    </a></li>`;
                });
            } else {
                listaAmigos = '<p>No tienes amigos aún.</p>';
            }
            $('.amigos-lista').html('<ul>' + listaAmigos + '</ul>');
        }

        // Alternar el estado de la variable listaVisible
        listaVisible = !listaVisible;
    });

    // Añadir confirmación al hacer clic en "Borrar Amistad"
    $(document).on('click', '.borrar-amigo', function(event) {
        event.preventDefault();  // Evitar la redirección directa

        let borrarUrl = $(this).data('url');  // Obtener la URL del atributo data-url

        // Mostrar la ventana de confirmación
        if (confirm("¿Estás seguro de que deseas borrar a este amigo?")) {
            // Si el usuario confirma, redirigir a la URL de borrar
            window.location.href = borrarUrl;
        }
    });

    // Mostrar popup para enviar solicitud de amistad
    $('#enviar_solicitud').on('click', function() {
        $('#popup-enviar-solicitud').fadeIn();
    });

    $('#enviar-solicitud').on('click', function(){
        window.alert("¿Seguro que quieres enviar una solicitud a este usuario?")
    });

    // Cerrar popup de enviar solicitud
    $('#closePopupEnviar').on('click', function() {
        $('#popup-enviar-solicitud').fadeOut();
    });

    // Mostrar popup de solicitudes pendientes
        $('#ver_solicitudes').on('click', function() {
        let listaSolicitudes = '';
        if (solicitudes.length > 0) {
            solicitudes.forEach(function(solicitud) {
                let añadirAmigoUrl = añadirAmigoUrlBase + solicitud[0];  // Concatenar el username del amigo
                listaSolicitudes += `<li><strong>${solicitud[0]}</strong><a href="#" class="añadir-amigo" data-url="${añadirAmigoUrl}">
                    <img src="${aceptarIconUrl}" alt="Aceptar" class="cerrarbtn">
                </a></li>`;
            });
        } else {
            listaSolicitudes = '<p>No tienes solicitudes pendientes.</p>';
        }
        $('#lista-solicitudes').html(listaSolicitudes);
        $('#popup-solicitudes-pendientes').fadeIn();
    });

        // Añadir confirmación al hacer clic en "Borrar Amistad"
    $(document).on('click', '.añadir-amigo', function(event) {
        event.preventDefault();  // Evitar la redirección directa

        let añadirUrl = $(this).data('url');  // Obtener la URL del atributo data-url

        // Mostrar la ventana de confirmación
        if (confirm("¿Estás seguro de que deseas añadir a este amigo?")) {
            // Si el usuario confirma, redirigir a la URL de borrar
            window.location.href = añadirUrl;
        }
    });

    // Cerrar popup de solicitudes pendientes
    $('#closePopupSolicitudes').on('click', function() {
        $('#popup-solicitudes-pendientes').fadeOut();
    });
});

    const obtenerUsuariosUrl = "/obtener_usuarios"; // Esto generará la URL completa    $(document).ready(function() {
    $('#button-search').on('click', function(event) {
        event.preventDefault();

        // Lógica para mostrar el menú, creándolo solo si no existe
        if ($('.dropdown-list li').length === 0) {
            $.ajax({
                url: obtenerUsuariosUrl,
                method: "GET",
                success: function(data) {
                    let dropdownHtml = '';
                    data.usuarios.forEach(function(usuario) {
                        dropdownHtml += `<li class="user-item">${usuario}</li>`;
                    });
                    $('.dropdown-list').html(dropdownHtml).show();  // Añade los elementos y muestra la lista

                    // Evento para completar el input al hacer clic en un usuario
                    $('.user-item').on('click', function() {
                        const selectedUser = $(this).text();
                        $('#friend_username').val(selectedUser);  // Completa el campo con el nombre del usuario
                        $('.dropdown-list').hide();  // Oculta el menú después de seleccionar
                    });
                },
                error: function(error) {
                    console.error("Error al obtener usuarios:", error);
                }
            });
        } else {
            $('.dropdown-list').toggle();  // Alterna la visibilidad si la lista ya existe
        }
    });

    // Ocultar el menú cuando se hace clic fuera de él
    $(document).on('click', function(event) {
        if (!$(event.target).closest('#button-search').length &&
            !$(event.target).closest('.dropdown-list').length) {
            $('.dropdown-list').hide();  // Oculta el menú desplegable
        }
    });

$(document).on('click', '#deletebtn', function() {
    const name_test = $(this).closest('li').find('strong').text();

    const confirmDelete = confirm("¿Estás seguro de que quieres eliminar este resultado?");
    if (confirmDelete) {
        $.ajax({
            url: '/delete_result',
            type: 'POST',
            data: { name_test: name_test },
            success: function(response) {
                if (response.error) {
                    alert(response.error);
                } else {
                    location.reload(); // Recargar la página del perfil
                }
            },
            error: function() {
                alert("Error al eliminar el resultado. Por favor, inténtelo de nuevo.");
            }
        });
    }
});