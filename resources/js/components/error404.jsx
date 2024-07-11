import React from 'react';
import { Link } from 'react-router-dom';

export default function NotFound() {
    return (
        <div>
            <img src="/images/404.svg" alt="404 Not Found" />
            <p>Oops! Page not found.</p>
            <Link to="/">Go back to home</Link>
        </div>
    );
}
