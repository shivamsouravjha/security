import React, { useState, useEffect } from 'react';
import { useDispatch } from 'react-redux';
import { setToken } from '../redux/authSlice';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { ToastContainer, toast } from 'react-toastify'; // Import Toast components
import 'react-toastify/dist/ReactToastify.css'; // Import Toast CSS

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [step, setStep] = useState(1);
  const dispatch = useDispatch();
  const navigate = useNavigate();

  useEffect(() => {
    const checkAuthStatus = async () => {
      try {
        const response = await axios.get('https://localhost:8000/api/me/', {
          withCredentials: true,
        });
        if (response.status === 200) {
          navigate('/dashboard');
        }
      } catch {
        console.log('User is not logged in');
      }
    };
    checkAuthStatus();
  }, [navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();

    if (step === 1) {
      try {
        await axios.post(
          'https://localhost:8000/api/login/',
          { username, password, step: '1' },
          {
            headers: {
              'Content-Type': 'application/json',
            },
            withCredentials: true,
          }
        );
        setStep(2);
      } catch (error) {
        if (error.response && error.response.status === 403) {
          const errorData = error.response.data;
          if (errorData.error === 'MFA is not enabled' && errorData.redirect) {
            // Redirect user to the enable MFA page
            toast.info("MFA is not enabled. Redirecting to MFA setup page.");

            // Delay navigation to allow the toast to display
            setTimeout(() => {
              navigate(errorData.redirect, { state: { username, password } });
            }, 2000); // Delay of 2 seconds
            return;
          }
        }
        console.error('Login failed:', error.response ? error.response.data : error.message);
        const errorMessage =
          error.response?.data?.error || 'Login failed. Please try again.';
        toast.error(errorMessage); // Show toast notification for login failure
      }
    } else if (step === 2) {
      try {
        await axios.post(
          'https://localhost:8000/api/login/',
          { username, totp, step: '2' },
          {
            headers: {
              'Content-Type': 'application/json',
            },
            withCredentials: true,
          }
        );
        dispatch(setToken('VALID_SESSION'));
        navigate('/dashboard');
      } catch (error) {
        const errorMessage =
          error.response?.data?.error || 'TOTP verification failed. Please try again.';
        toast.error(errorMessage); // Show toast notification for TOTP failure
      }
    }
  };

  return (
    <div>
      <ToastContainer /> {/* Toast container for notifications */}
      <form onSubmit={handleLogin}>
        <h1>Login</h1>
        {step === 1 && (
          <>
            <div>
              <label>Username:</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label>Password:</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </>
        )}
        {step === 2 && (
          <div>
            <label>Enter TOTP Code:</label>
            <input
              type="text"
              value={totp}
              onChange={(e) => setTotp(e.target.value)}
              required
            />
          </div>
        )}
        <button type="submit">
          {step === 1 ? 'Validate Credentials' : 'Login'}
        </button>
      </form>
    </div>
  );
};

export default LoginPage;
