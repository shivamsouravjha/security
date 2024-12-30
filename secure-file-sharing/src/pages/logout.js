import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { setToken } from '../redux/authSlice'; // Clear token in Redux

const logout = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleLogout = () => {
    // Clear tokens from localStorage
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');

    // Clear authentication state in Redux
    dispatch(setToken(null));

    // Redirect to login page
    navigate('/login');
  };

  return <button onClick={handleLogout}>Logout</button>;
};

export default logout;
