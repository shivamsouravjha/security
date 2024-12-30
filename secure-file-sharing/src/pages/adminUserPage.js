import React, { useEffect, useState } from 'react';
import { fetchCsrfToken } from '../utils/csrf';
import apiClient from '../utils/apiClient';

const AdminUserPage = () => {
  const [users, setUsers] = useState([]);
  const [selectedRole, setSelectedRole] = useState({}); // Keep track of role changes
  const token = localStorage.getItem('accessToken'); // Retrieve JWT token from storage

  // Fetch all users
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await apiClient.get('https://localhost:8000/api/admin/users/', {});
        setUsers(response.data.results || response.data); // Adjust based on response format
      } catch (error) {
        console.error('Error fetching users:', error.response?.data || error.message);
      }
    };

    fetchUsers();
    fetchCsrfToken();
  }, [token]);

  // Delete a user
  const deleteUser = async (userId) => {
    try {
      await apiClient.delete(`https://localhost:8000/api/admin/users/${userId}/`, {
        withCredentials: true, // Ensure cookies are sent with the request
      });
      // Update the user list after deletion
      setUsers(users.filter((user) => user.id !== userId));
    } catch (error) {
      console.error('Error deleting user:', error.response?.data || error.message);
    }
  };

  // Update a user's role
  const updateUserRole = async (userId, role) => {
    try {
      await apiClient.patch(
        `https://localhost:8000/api/admin/users/${userId}/`,
        { role },
        {

        }
      );
      // Update the user role in the state
      setUsers(users.map((user) =>
        user.id === userId ? { ...user, role } : user
      ));
      alert('User role updated successfully.');
    } catch (error) {
      console.error('Error updating user role:', error.response?.data || error.message);
      alert('Failed to update user role.');
    }
  };

  return (
    <div>
      <h1>Admin: Manage Users</h1>
      <ul>
        {users.map((user) => (
          <li key={user.id}>
            {user.username} - {user.email} - Role: {user.role}
            <button onClick={() => deleteUser(user.id)}>Delete</button>
            <select
              value={selectedRole[user.id] || user.role} // Use selected role or default to user's current role
              onChange={(e) => setSelectedRole({ ...selectedRole, [user.id]: e.target.value })}
            >
              <option value="guest">Guest</option>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
            <button
              onClick={() => updateUserRole(user.id, selectedRole[user.id] || user.role)}
            >
              Update Role
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default AdminUserPage;
