import React from 'react';
import { useNavigate } from 'react-router-dom';

const HomePage = () => {
  const navigate = useNavigate();

  const handleNavigate = (path) => {
    navigate(path);
  };

  return (
    <div style={{ textAlign: 'center', padding: '50px' }}>
      <h1>Welcome to Secure File Sharing</h1>
      <p>Please choose an option to proceed:</p>
      <div>
        <button
          onClick={() => handleNavigate('/login')}
          style={{ margin: '10px', padding: '10px 20px' }}
        >
          Login
        </button>
        <button
          onClick={() => handleNavigate('/register')}
          style={{ margin: '10px', padding: '10px 20px' }}
        >
          Sign Up
        </button>
      </div>
    </div>
  );
};

export default HomePage;
