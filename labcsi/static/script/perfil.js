
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
    });// cutfreq.cpp
#include "../common/binario.hpp"
#include "cutfreq.hpp"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <limits>

namespace {

std::unordered_map<uint32_t, int> calcularFrecuenciaColores(const PPMImage& image) {
    std::unordered_map<uint32_t, int> colorFrequency;
    for (std::size_t i = 0; i < image.pixelData.size(); i += 3) {
        const uint32_t color = (static_cast<uint32_t>(image.pixelData[i]) << SHIFT_RED) |
                               (static_cast<uint32_t>(image.pixelData[i + 1]) << SHIFT_GREEN) |
                               static_cast<uint32_t>(image.pixelData[i + 2]);
        colorFrequency[color]++;
    }
    return colorFrequency;
}

std::vector<uint32_t> obtenerColoresMenosFrecuentes(const std::unordered_map<uint32_t, int>& colorFrequency, int n) {
    std::vector<std::pair<uint32_t, int>> frequencyList(colorFrequency.begin(), colorFrequency.end());
    std::ranges::sort(frequencyList, [](const auto& colorA, const auto& colorB) {
        if (colorA.second != colorB.second) {
            return colorA.second < colorB.second;
        }
        if ((colorA.first & MASK) != (colorB.first & MASK)) {
            return (colorA.first & MASK) > (colorB.first & MASK);
        }
        if (((colorA.first >> SHIFT_GREEN) & MASK) != ((colorB.first >> SHIFT_GREEN) & MASK)) {
            return ((colorA.first >> SHIFT_GREEN) & MASK) > ((colorB.first >> SHIFT_GREEN) & MASK);
        }
        return ((colorA.first >> SHIFT_RED) & MASK) > ((colorB.first >> SHIFT_RED) & MASK);
    });

    std::vector<uint32_t> colorsToRemove;
    const std::size_t limit = static_cast<std::size_t>(std::min(n, static_cast<int>(frequencyList.size())));
    colorsToRemove.reserve(limit);
    for (std::size_t i = 0; i < limit; ++i) {
        colorsToRemove.push_back(frequencyList[i].first);
    }
    return colorsToRemove;
}

std::unordered_map<uint32_t, uint32_t> encontrarColoresReemplazo(const std::vector<std::pair<uint32_t, int>>& frequencyList, const std::unordered_set<uint32_t>& colorsToRemoveSet) {
    std::unordered_map<uint32_t, uint32_t> replacementMap;
    for (const auto& colorToRemove : colorsToRemoveSet) {
        double minDistance = std::numeric_limits<double>::max();
        uint32_t closestColor = 0;
        for (const auto& [candidateColor, freq] : frequencyList) {
            if (colorsToRemoveSet.find(candidateColor) == colorsToRemoveSet.end()) {
                const double distance = std::sqrt(
                    std::pow(static_cast<int>((colorToRemove >> SHIFT_RED) & MASK) - static_cast<int>((candidateColor >> SHIFT_RED) & MASK), 2) +
                    std::pow(static_cast<int>((colorToRemove >> SHIFT_GREEN) & MASK) - static_cast<int>((candidateColor >> SHIFT_GREEN) & MASK), 2) +
                    std::pow(static_cast<int>(colorToRemove & MASK) - static_cast<int>(candidateColor & MASK), 2)
                );
                if (distance < minDistance) {
                    minDistance = distance;
                    closestColor = candidateColor;
                }
            }
        }
        replacementMap[colorToRemove] = closestColor;
    }
    return replacementMap;
}

void reemplazarColores(PPMImage& image, const std::unordered_map<uint32_t, uint32_t>& replacementMap) {
    for (std::size_t i = 0; i < image.pixelData.size(); i += 3) {
        const uint32_t color = (static_cast<uint32_t>(image.pixelData[i]) << SHIFT_RED) |
                               (static_cast<uint32_t>(image.pixelData[i + 1]) << SHIFT_GREEN) |
                               static_cast<uint32_t>(image.pixelData[i + 2]);
        auto iterator = replacementMap.find(color);
        if (iterator != replacementMap.end()) {
            const uint32_t newColor = iterator->second;
            image.pixelData[i] = (newColor >> SHIFT_RED) & MASK;
            image.pixelData[i + 1] = (newColor >> SHIFT_GREEN) & MASK;
            image.pixelData[i + 2] = newColor & MASK;// cutfreq.cpp
#include "../common/binario.hpp"
#include "cutfreq.hpp"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <iostream>
#include <limits>

namespace {

std::unordered_map<uint32_t, int> calcularFrecuenciaColores(const PPMImage& image) {
    std::unordered_map<uint32_t, int> colorFrequency;
    for (std::size_t i = 0; i < image.pixelData.size(); i += 3) {
        const uint32_t color = (static_cast<uint32_t>(image.pixelData[i]) << SHIFT_RED) |
                               (static_cast<uint32_t>(image.pixelData[i + 1]) << SHIFT_GREEN) |
                               static_cast<uint32_t>(image.pixelData[i + 2]);
        colorFrequency[color]++;
    }
    return colorFrequency;
}

std::vector<uint32_t> obtenerColoresMenosFrecuentes(const std::unordered_map<uint32_t, int>& colorFrequency, int n) {
    std::vector<std::pair<uint32_t, int>> frequencyList(colorFrequency.begin(), colorFrequency.end());
    std::ranges::sort(frequencyList, [](const auto& colorA, const auto& colorB) {
        if (colorA.second != colorB.second) {
            return colorA.second < colorB.second;
        }
        if ((colorA.first & MASK) != (colorB.first & MASK)) {
            return (colorA.first & MASK) > (colorB.first & MASK);
        }
        if (((colorA.first >> SHIFT_GREEN) & MASK) != ((colorB.first >> SHIFT_GREEN) & MASK)) {
            return ((colorA.first >> SHIFT_GREEN) & MASK) > ((colorB.first >> SHIFT_GREEN) & MASK);
        }
        return ((colorA.first >> SHIFT_RED) & MASK) > ((colorB.first >> SHIFT_RED) & MASK);
    });

    std::vector<uint32_t> colorsToRemove;
    const std::size_t limit = static_cast<std::size_t>(std::min(n, static_cast<int>(frequencyList.size())));
    colorsToRemove.reserve(limit);
    for (std::size_t i = 0; i < limit; ++i) {
        colorsToRemove.push_back(frequencyList[i].first);
    }
    return colorsToRemove;
}

std::unordered_map<uint32_t, uint32_t> encontrarColoresReemplazo(const std::vector<std::pair<uint32_t, int>>& frequencyList, const std::unordered_set<uint32_t>& colorsToRemoveSet) {
    std::unordered_map<uint32_t, uint32_t> replacementMap;
    for (const auto& colorToRemove : colorsToRemoveSet) {
        double minDistance = std::numeric_limits<double>::max();
        uint32_t closestColor = 0;
        for (const auto& [candidateColor, freq] : frequencyList) {
            if (colorsToRemoveSet.find(candidateColor) == colorsToRemoveSet.end()) {
                const double distance = std::sqrt(
                    std::pow(static_cast<int>((colorToRemove >> SHIFT_RED) & MASK) - static_cast<int>((candidateColor >> SHIFT_RED) & MASK), 2) +
                    std::pow(static_cast<int>((colorToRemove >> SHIFT_GREEN) & MASK) - static_cast<int>((candidateColor >> SHIFT_GREEN) & MASK), 2) +
                    std::pow(static_cast<int>(colorToRemove & MASK) - static_cast<int>(candidateColor & MASK), 2)
                );
                if (distance < minDistance) {
                    minDistance = distance;
                    closestColor = candidateColor;
                }
            }
        }
        replacementMap[colorToRemove] = closestColor;
    }
    return replacementMap;
}

void reemplazarColores(PPMImage& image, const std::unordered_map<uint32_t, uint32_t>& replacementMap) {
    for (std::size_t i = 0; i < image.pixelData.size(); i += 3) {
        const uint32_t color = (static_cast<uint32_t>(image.pixelData[i]) << SHIFT_RED) |
                               (static_cast<uint32_t>(image.pixelData[i + 1]) << SHIFT_GREEN) |
                               static_cast<uint32_t>(image.pixelData[i + 2]);
        auto iterator = replacementMap.find(color);
        if (iterator != replacementMap.end()) {
            const uint32_t newColor = iterator->second;
            image.pixelData[i] = (newColor >> SHIFT_RED) & MASK;
            image.pixelData[i + 1] = (newColor >> SHIFT_GREEN) & MASK;
            image.pixelData[i + 2] = newColor & MASK;
        }
    }
}

} // namespace

void cutfreq(PPMImage& image, int n) {
    auto colorFrequency = calcularFrecuenciaColores(image);
    auto colorsToRemove = obtenerColoresMenosFrecuentes(colorFrequency, n);

    std::vector<std::pair<uint32_t, int>> frequencyList(colorFrequency.begin(), colorFrequency.end());
    std::ranges::sort(frequencyList, [](const auto& colorA, const auto& colorB) {
        if (colorA.second != colorB.second) {
            return colorA.second < colorB.second;
        }
        if ((colorA.first & MASK) != (colorB.first & MASK)) {
            return (colorA.first & MASK) > (colorB.first & MASK);
        }
        if (((colorA.first >> SHIFT_GREEN) & MASK) != ((colorB.first >> SHIFT_GREEN) & MASK)) {
            return ((colorA.first >> SHIFT_GREEN) & MASK) > ((colorB.first >> SHIFT_GREEN) & MASK);
        }
        return ((colorA.first >> SHIFT_RED) & MASK) > ((colorB.first >> SHIFT_RED) & MASK);
    });

    const std::unordered_set<uint32_t> colorsToRemoveSet(colorsToRemove.begin(), colorsToRemove.end());
    auto replacementMap = encontrarColoresReemplazo(frequencyList, colorsToRemoveSet);

    reemplazarColores(image, replacementMap);
}

        }
    }
}

} // namespace

void cutfreq(PPMImage& image, int n) {
    auto colorFrequency = calcularFrecuenciaColores(image);
    auto colorsToRemove = obtenerColoresMenosFrecuentes(colorFrequency, n);

    std::vector<std::pair<uint32_t, int>> frequencyList(colorFrequency.begin(), colorFrequency.end());
    std::ranges::sort(frequencyList, [](const auto& colorA, const auto& colorB) {
        if (colorA.second != colorB.second) {
            return colorA.second < colorB.second;
        }
        if ((colorA.first & MASK) != (colorB.first & MASK)) {
            return (colorA.first & MASK) > (colorB.first & MASK);
        }
        if (((colorA.first >> SHIFT_GREEN) & MASK) != ((colorB.first >> SHIFT_GREEN) & MASK)) {
            return ((colorA.first >> SHIFT_GREEN) & MASK) > ((colorB.first >> SHIFT_GREEN) & MASK);
        }
        return ((colorA.first >> SHIFT_RED) & MASK) > ((colorB.first >> SHIFT_RED) & MASK);
    });

    const std::unordered_set<uint32_t> colorsToRemoveSet(colorsToRemove.begin(), colorsToRemove.end());
    auto replacementMap = encontrarColoresReemplazo(frequencyList, colorsToRemoveSet);

    reemplazarColores(image, replacementMap);
}


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
