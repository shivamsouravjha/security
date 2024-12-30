import axios from 'axios';

// Create an Axios instance
const apiClient = axios.create({
  baseURL: 'https://localhost:8000/api/',
  withCredentials: true,  // important to send HttpOnly cookies
});

async function refreshAccessToken() {
  try {
    // Make a POST (or GET) request to your refresh endpoint
    // The server should use the 'refresh_token' cookie to issue a new 'access_token' cookie
    await axios.post('https://localhost:8000/api/refresh/', {}, {
      withCredentials: true,
    });
  } catch (err) {
    // If refresh fails (e.g., invalid refresh token), handle it (e.g., logout or redirect)
    console.error('Failed to refresh access token:', err);
    throw err;
  }
}
// You can keep a basic error handler:
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If we get a 401, and we haven't already retried this request,
    // try to refresh the token.
    if (error.response && error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true; // Prevent infinite loop

      try {
        await refreshAccessToken();
        return apiClient(originalRequest);
      } catch (refreshError) {
        console.error('Refresh token also failed:', refreshError);
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);


export default apiClient;
