function toggleProfileMenu() {
    var profileDropdown = document.getElementById("profileDropdown");
    if (profileDropdown.style.display === "block") {
        profileDropdown.style.display = "none";
    } else {
        profileDropdown.style.display = "block";
    }
}

function toggleNavbar() {
    var navbarMenu = document.querySelector(".navbar-menu");
    if (navbarMenu.style.display === "flex") {
        navbarMenu.style.display = "none";
    } else {
        navbarMenu.style.display = "flex";
    }
}
