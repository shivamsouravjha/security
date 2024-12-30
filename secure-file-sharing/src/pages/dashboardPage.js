import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import FileUpload from '../components/fileUpload';
import FileList from '../components/fileList';
import AdminFilePage from '../pages/adminPage';
import AdminUserPage from '../pages/adminUserPage';
import apiClient from '../utils/apiClient';
const DashboardPage = () => {
    const navigate = useNavigate();
    const [user, setUser] = useState(null);

    const handleLogout = async () => {
        try {
            // Call the API to log out (clears cookies)
            await apiClient.post('https://localhost:8000/api/logout/', {}, {
                withCredentials: true, // Include cookies in the request
            });
            // Clear local state or storage (if used for other non-secure data)
            setUser(null); // Clear user state
            // Redirect to the login page
            navigate('/login');
        } catch (error) {
            console.error('Error logging out:', error);
            
            // Optionally display an error message to the user
        }
    };


    useEffect(() => {
        async function fetchUser() {
            try {
                console.log('fetching user',);
                // The server will check your HttpOnly cookies automatically
                const response = await apiClient.get('https://localhost:8000/api/me/', {
                    withCredentials: true,
                });
                setUser(response.data);
            } catch (error) {
                navigate('/login');
                console.error('Error fetching user:', error);
                // handle not-authenticated or other error
            }
        }

        fetchUser();
    }, [navigate]);


    return (
        <div>
            <h1>{user?.role === 'admin' ? 'Admin Dashboard' : 'User Dashboard'}</h1>
            <button onClick={handleLogout}>Logout</button>
            <FileUpload />
            <FileList />
            {user?.role === 'admin' && (
                <div>
                    <h2>Admin-Specific Actions</h2>
                    <AdminFilePage />
                    <AdminUserPage />
                </div>
            )}
        </div>
    );
};

export default DashboardPage;
