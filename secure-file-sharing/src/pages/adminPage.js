import React, { useEffect, useState } from 'react';
import apiClient from '../utils/apiClient';
import { fetchCsrfToken } from '../utils/csrf';
import { handleDownloadFile, handleViewFile } from '../utils/fileUtils';

const AdminFilePage = () => {

  const [files, setFiles] = useState([]);
  const token = localStorage.getItem('accessToken'); // Retrieve JWT token from storage
  const [previewFile, setPreviewFile] = useState(null); // Content for view-only preview

  useEffect(() => {
    fetchCsrfToken();
  }, [token]);

  // Fetch all files
  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const response = await apiClient.get('https://localhost:8000/api/admin/files/', {});
        setFiles(response.data.results || response.data); // Adjust based on response format
      } catch (error) {
        console.error('Error fetching files:', error.response?.data || error.message);
      }
    };

    fetchFiles();
  }, [token]);

  // Delete a file
  const deleteFile = async (fileId) => {
    try {
      await apiClient.delete(`https://localhost:8000/api/admin/files/${fileId}/`, {});
      // Update the file list after deletion
      setFiles(files.filter((file) => file.id !== fileId));
    } catch (error) {
      console.error('Error deleting file:', error.response?.data || error.message);
    }
  };

  return (
    <div>
      <h1>Admin: Manage Files</h1>
      <ul>
        {files.map((file) => (
          <li key={file.id}>
            {file.original_filename} - Owner: {file.owner}
            <button onClick={() => deleteFile(file.id)}>Delete</button>
            <button onClick={() => handleDownloadFile(file.uuid, file.name)}>Download</button>
            <button onClick={() => handleViewFile(setPreviewFile, file.uuid)}>View</button>
          </li>
        ))}

        {previewFile && (
          <div style={{ border: '1px solid #ccc', padding: '20px', marginTop: '20px' }}>
            <h3>File Preview</h3>
            <button onClick={() => setPreviewFile(null)}>Close Preview</button>
            {previewFile.type === 'image' ? (
              <img
                src={previewFile.url}
                alt="Preview of uploaded file"
                style={{ maxWidth: '100%', maxHeight: '500px' }}
              />
            ) : previewFile.type === 'text' ? (
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {previewFile.content}
              </pre>
            ) : (
              <iframe
                src={previewFile.url}
                title="File Preview"
                style={{ width: '100%', height: '500px' }}
              ></iframe>
            )}
          </div>
        )}
      </ul>
    </div>
  );
};

export default AdminFilePage;
