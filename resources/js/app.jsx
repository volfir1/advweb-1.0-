import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import Header from './components/header'; // Adjust the import path based on your actual structure
import Sidebar from './components/Sidebar'; // Adjust the import path based on your actual structure
import axios from 'axios';
import '../css/app.css';

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const fetchUserProfile = async () => {
      try {
        const response = await axios.get('/api/user-profile');
        setUser(response.data); // Assuming response.data contains user profile data
      } catch (error) {
        console.error('Error fetching user profile:', error);
      }
    };

    fetchUserProfile();
  }, []);

  if (!user) {
    return <div>Loading...</div>; // Add a loading indicator or handle the loading state
  }

  const role = user.role === 'admin' ? 'admin' : 'customer'; // Assuming user.role is properly set

  return (
    <div className="App">
      <Header user={{ ...user, role }} /> {/* Pass user and role to Header */}
      <div className="main-wrapper">
        {role === 'admin' && <Sidebar />} {/* Render Sidebar based on user role */}
        <div className="content">
          {/* Other content */}
        </div>
      </div>
    </div>
  );
}

document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('hello-react');
  if (container) {
    const root = ReactDOM.createRoot(container);
    root.render(<App />);
  } else {
    console.error('Element with id "hello-react" not found.');
  }
});

export default App;
