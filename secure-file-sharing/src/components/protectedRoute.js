import { Navigate, Outlet } from 'react-router-dom';
import React, { useState, useEffect } from 'react';
import apiClient from '../utils/apiClient';
import { useNavigate } from 'react-router-dom';

const ProtectedRoute = ({ requiredRole }) => {
  const [userRole, setUserRole] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchUserRole() {
      try {
        const response = await apiClient.get('https://localhost:8000/api/me/', {
          withCredentials: true,
        });
        setUserRole(response.data.role);
      } catch (error) {
        console.error('Error fetching user role:', error);
        navigate('/login');
      } finally {
        setLoading(false);
      }
    }

    fetchUserRole();
  }, [navigate]);

  const hasAccess = () => {
    if (!userRole) return false;
    if (requiredRole && userRole !== requiredRole) {
      return false; // Redirect if the user lacks the required role
    }
    return true;
  };

  if (loading) {
    return <div>Loading...</div>; // Optionally show a loader
  }

  return hasAccess() ? <Outlet /> : <Navigate to="/dashboard" />;
};

export default ProtectedRoute;
