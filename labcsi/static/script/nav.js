function toggleDropdown(event) {
    event.stopPropagation(); // Detiene la propagación del evento para evitar que se oculte inmediatamente
    const dropdownMenu = document.getElementById("dropdown-menu");
    dropdownMenu.style.display = dropdownMenu.style.display === "block" ? "none" : "block";
}

// Para cerrar el menú desplegable cuando se hace clic fuera de él
window.onclick = function(event) {
    const dropdownMenu = document.getElementById("dropdown-menu");
    const perfilImagen = document.getElementById("imagen-perfil");

    // Si el clic no es en el menú desplegable ni en la imagen de perfil, se cierra el menú
    if (dropdownMenu.style.display === "block" && event.target !== dropdownMenu && event.target !== perfilImagen) {
        dropdownMenu.style.display = "none";
    }
};