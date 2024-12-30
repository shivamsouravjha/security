import apiClient from '../utils/apiClient';

/**
 * Fetch the CSRF token securely.
 */
export const fetchCsrfToken = async () => {
  try {
    await apiClient.get(`https://localhost:8000/api/csrf/`, {
    });
  } catch (error) {
    console.error('Error fetching CSRF token:', error.response?.data || error.message);
  }
};
