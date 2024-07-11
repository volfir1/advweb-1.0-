import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import PersonRoundedIcon from '@mui/icons-material/PersonRounded';
import ExitToAppRoundedIcon from '@mui/icons-material/ExitToAppRounded';
import ShoppingCartIcon from '@mui/icons-material/ShoppingCart';
import '../../css/admin-header.css';

function Header({ user }) {
  const [dropdownVisible, setDropdownVisible] = useState(false);
  const [cartHovered, setCartHovered] = useState(false);
  const [imageError, setImageError] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const toggleDropdown = () => setDropdownVisible(!dropdownVisible);

  const handleLogout = async () => {
    if (isLoggingOut) return;
    setIsLoggingOut(true);
    try {
      await axios.post('/api/logout');
      setTimeout(() => {
        window.location.href = '/home'; // Redirect after logout
      }, 100);
    } catch (error) {
      console.error('Error during logout:', error);
      alert('Logout failed. Please try again.');
      setIsLoggingOut(false);
    }
  };

  const getWelcomeMessage = () => {
    let roleMessage = '';
    if (user && user.role === 'admin') {
      roleMessage = 'Admin';
    } else if (user && user.role === 'customer') {
      roleMessage = 'Customer';
    }
    return `Welcome ${roleMessage}, ${user ? user.name : ''}`;
  };

  const handleImageError = () => {
    setImageError(true);
    console.error('Failed to load profile image');
  };

  const getImageSrc = () => {
    if (!user || !user.profile_image) {
      return 'https://via.placeholder.com/40'; // Placeholder image URL
    }
    try {
      const imageUrl = user.profile_image.startsWith('http')
        ? user.profile_image
        : `/storage/profile_images/${user.profile_image}`;
      return imageUrl;
    } catch (error) {
      console.error('Error getting image source:', error);
      return 'https://via.placeholder.com/40'; // Placeholder image URL
    }
  };

  useEffect(() => {
    if (user && user.profile_image) {
      const img = new Image();
      img.src = getImageSrc();
      img.onerror = handleImageError;
    }
  }, [user]);

  if (!user) {
    return null; // or Loading indicator, depending on your design
  }

  return (
    <header className="header">
      <div className="header-content">
        <img src="../logos/baketogo.jpg" alt="Company Logo" className="logo" />
        {user.role === 'customer' && (
          <div className="search-bar">
            <input type="text" placeholder="Search..." className="search-input" />
            <SearchRoundedIcon className="search-icon" />
          </div>
        )}
        <div className="right-section">
          {user.role === 'customer' && (
            <div
              className="cart-icon-container"
              onMouseEnter={() => setCartHovered(true)}
              onMouseLeave={() => setCartHovered(false)}
            >
              <ShoppingCartIcon className="cart-icon" />
              {cartHovered && (
                <div className="cart-popup">
                  <div className="cart-popup-content">
                    <img src="/path/to/no-products-icon.png" alt="No Products" className="no-products-icon" />
                    <p>No Products Yet</p>
                  </div>
                </div>
              )}
            </div>
          )}
          <div
            className="profile-section"
            onClick={toggleDropdown}
            role="button"
            tabIndex={0}
            aria-haspopup="true"
            aria-expanded={dropdownVisible}
            onKeyPress={(e) => e.key === 'Enter' && toggleDropdown()}
          >
            <img
              src={getImageSrc()}
              alt="Profile"
              className="profile-pic"
              onError={handleImageError}
            />
            <span className="welcome-message">{getWelcomeMessage()}</span>
            <ul className={`profile-dropdown ${dropdownVisible ? 'visible' : ''}`}>
              <li>
                <PersonRoundedIcon className="dropdown-icon" />
                <a href="/manage-profile">Manage Profile</a>
              </li>
              <li>
                <ExitToAppRoundedIcon className="dropdown-icon" />
                <button onClick={handleLogout} disabled={isLoggingOut}>
                  {isLoggingOut ? 'Logging out...' : 'Logout'}
                </button>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </header>
  );
}

Header.propTypes = {
  user: PropTypes.shape({
    name: PropTypes.string.isRequired,
    email: PropTypes.string.isRequired,
    role: PropTypes.string.isRequired,
    profile_image: PropTypes.string, // Assuming profile_image is optional
  }),
};

export default Header;
