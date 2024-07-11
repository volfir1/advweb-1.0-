<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Navbar</title>
    <link rel="stylesheet" href="../assets/css/customerheader.css" />
</head>
<body>
    <header>
        <nav class="navbar">
            <div class="container">
                <a href="#" class="navbar-brand"><img src="assets/images/logos/bake-logo.jpg" alt="Brand Logo"></a>
                <div class="navbar-middle">
                    <div class="search-container">
                        <input type="text" class="search-bar" placeholder="Search now">
                        <button class="search-icon-button" onclick="searchFunction()">
                            <img src="assets/icons/search.svg" alt="Search Icon">
                        </button>
                    </div>
                </div>
                <div class="navbar-icons">
                    <a href="#" class="cart-link"><img src="assets/icons/cart.svg" alt="Cart Icon"></a>
                    <div class="profile-link" onclick="toggleProfileMenu()">
                        <img src="assets/faces/face1.jpg" alt="Profile Icon">
                        <div class="dropdown-menu" id="profileDropdown">
                            <ul class="navbar-nav">
                                <li class="nav-item"><a href="#" class="nav-link">Settings</a></li>
                                <li class="nav-item"><a href="#" class="nav-link">Logout</a></li>
                            </ul>
                        </div>
                    </div>
                </div>
                <button class="navbar-toggler" type="button" onclick="toggleNavbar()">
                    <span class="navbar-toggler-icon">&#9776;</span>
                </button>
            </div>
        </nav>
    </header>

    <script src="../assets/js/customerheader.js"></script>
</body>
</html>
