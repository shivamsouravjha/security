import { createSlice } from '@reduxjs/toolkit';

// Create the slice
const authSlice = createSlice({
    name: 'auth',
    initialState: {
        token: localStorage.getItem('accessToken') || null, // Load token from localStorage
        isAuthenticated: !!localStorage.getItem('accessToken'),
    },
    reducers: {
        setToken(state, action) {
            state.token = action.payload;
            state.isAuthenticated = true;
            localStorage.setItem('accessToken', action.payload); // Store token in localStorage
        },
        clearToken(state) {
            state.token = null;
            state.isAuthenticated = false;
            localStorage.removeItem('accessToken'); // Clear token from localStorage
        },
    },
});

// Export the action for setting the token
export const { setToken, clearToken } = authSlice.actions;

// Export the reducer as the default export
export default authSlice.reducer;
