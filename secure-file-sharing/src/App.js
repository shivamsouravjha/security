import React from 'react';
import { Routes, Route } from 'react-router-dom';
import LoginPage from './pages/loginPage';
import HomePage from './pages/homePage';
import RegisterPage from './pages/registerPage';
import DashboardPage from './pages/dashboardPage';
import UserManagementPage from './pages/userManagementPage';
import FileSharingPage from './pages/shareFilePage';
import ProtectedRoute from './components/protectedRoute';
import DownloadPage from './pages/downloadPage';
import EnableMFA from './pages/enableMFA';
function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/enable-mfa" element={<EnableMFA />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/download/:token" element={<DownloadPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/users" element={<UserManagementPage />} />
        <Route path="/share/:fileId" element={<FileSharingPage />} />
      </Route>
    </Routes>
  );
}

export default App;
