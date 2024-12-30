import React, { useEffect, useState } from 'react';
import apiClient from '../utils/apiClient';
import { fetchCsrfToken } from '../utils/csrf';
const FileList = () => {
    const [files, setFiles] = useState([]);
    const [sharedFiles, setSharedFiles] = useState([]); // Files shared with the user
    const [searchResults, setSearchResults] = useState([]); // Search results for users
    const [error, setError] = useState(null);
    const [isSharing, setIsSharing] = useState(false); // Show/hide share form
    const [selectedFile, setSelectedFile] = useState(null); // File being shared
    const [searchQuery, setSearchQuery] = useState(''); // User search query
    const [selectedUser, setSelectedUser] = useState(null); // Selected user for sharing
    const [permission, setPermission] = useState('view'); // Selected permission
    const [expiry, setExpiry] = useState(60); // Default expiry time: 60 minutes
    const [generatedLink, setGeneratedLink] = useState(''); // Generated link
    const [previewFile, setPreviewFile] = useState(null); // Content for view-only preview

    function base64ToUint8Array(base64String) {
        const binaryString = atob(base64String);
        const binaryLength = binaryString.length;
        const bytes = new Uint8Array(binaryLength);
        for (let i = 0; i < binaryLength; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    async function decryptFile(encryptedFile, encryptionKey, iv) {
        // Import the encryption key
        const key = await window.crypto.subtle.importKey(
            'jwk',
            encryptionKey,
            {
                name: 'AES-GCM',
            },
            true,
            ['decrypt']
        );
        // Convert IV to Uint8Array
        const ivArray = new Uint8Array(iv);

        // Decrypt the file
        let decryptedData;
        try {
            decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivArray,
                },
                key,
                encryptedFile
            );
        } catch (error) {
            console.error("Decryption Error:", error);
            throw error; // Rethrow to handle higher up if needed
        }

        return decryptedData;
    }

    const handleViewFile = async (fileId) => {
        try {
            const token = localStorage.getItem('accessToken');
            const response = await apiClient.get(`https://localhost:8000/api/files/${fileId}/download/`, {
                headers: { Authorization: `Bearer ${token}` },
                responseType: 'json', // Get metadata for decryption
            });


            const { partially_decrypted_file, client_key, client_iv, original_filename } = response.data;
            const parsedKey = JSON.parse(client_key); // Parse the key
            const parsedIV = JSON.parse(client_iv); // Parse the IV
            const encryptedFileBuffer = base64ToUint8Array(partially_decrypted_file);
            const decryptedFile = await decryptFile(encryptedFileBuffer, parsedKey, parsedIV);
            if (original_filename.toLowerCase().endsWith('.txt')) {
                // Decode text content
                const decoder = new TextDecoder('utf-8'); // Adjust encoding as needed
                const textContent = decoder.decode(decryptedFile);
                setPreviewFile({ type: 'text', content: textContent });
            } else {
                // Handle binary files
                const blob = new Blob([decryptedFile], { type: 'image' });
                const objectURL = URL.createObjectURL(blob);

                setPreviewFile({ type: 'image', url: objectURL });
            }

        } catch (error) {
            setError('Failed to view the file. Please try again.', error);
        }
    };

    const handleDownloadFile = async (fileId, fileName) => {
        try {
            const token = localStorage.getItem('accessToken');
            const response = await apiClient.get(`https://localhost:8000/api/files/${fileId}/download/`, {
                headers: { Authorization: `Bearer ${token}` },
                responseType: 'json',
            });
            const { partially_decrypted_file, client_key, client_iv, original_filename } = response.data;
            const parsedKey = JSON.parse(client_key); // Parse the key
            const parsedIV = JSON.parse(client_iv); // Parse the IV
            const encryptedFileBuffer = base64ToUint8Array(partially_decrypted_file);
            const decryptedFile = await decryptFile(encryptedFileBuffer, parsedKey, parsedIV);
            const url = window.URL.createObjectURL(new Blob([new Uint8Array(decryptedFile)]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', original_filename);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            setError('Failed to download the file. Please try again.');
        }
    };

    useEffect(() => {
        fetchCsrfToken();
    }, []);

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const token = localStorage.getItem('accessToken');
                const filesResponse = await apiClient.get('https://localhost:8000/api/files/', {
                    headers: { Authorization: `Bearer ${token}` },
                });
                setFiles(filesResponse.data);

                const sharedFilesResponse = await apiClient.get(
                    'https://localhost:8000/api/files/shared-with-you/',
                    { headers: { Authorization: `Bearer ${token}` } }
                );
                setSharedFiles(sharedFilesResponse.data);
            } catch (error) {
                setError('Failed to fetch files. Please try again later.');
            }
        };

        fetchFiles();
    }, []);

    const handleSearchUsers = async (query) => {
        try {
            const token = localStorage.getItem('accessToken');
            const response = await apiClient.get(`https://localhost:8000/api/users/?search=${query}`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            setSearchResults(response.data);
        } catch (error) {
            setError('Failed to search users. Please try again.');
        }
    };
    const handleShareWithUsers = async () => {
        if (!selectedFile || !selectedUser) {
            alert('Please select a user and a file.');
            return;
        }

        try {
            const response = await apiClient.post(
                `https://localhost:8000/api/files/${selectedFile.id}/share/`,
                { users: [selectedUser], permission, expires_in: expiry * 60, user_id: selectedUser }, // Convert minutes to seconds
                {
                    withCredentials: true, // Include cookies for authentication
                }
            );
            const token = response.data.token; // Backend should return the UID
            const frontendLink = `http://localhost:3000/download/${token}`; // Construct frontend link
            setGeneratedLink(frontendLink);
            alert('File shared successfully!');
        } catch (error) {
            setError('Failed to share the file. Please try again.');
        }
    };

    const handleOpenShareForm = (file) => {
        setSelectedFile(file);
        setIsSharing(true);
        setGeneratedLink(''); // Reset the generated link
    };

    return (
        <div>
            <h2>Your Files</h2>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            {files.length > 0 ? (
                <ul>
                    {files.map((file) => (
                        <li key={file.uuid} style={{ marginBottom: '20px' }}>
                            <h4>{file.original_filename}</h4>
                            <p>Uploaded by: {file.owner}</p>
                            <button onClick={() => handleOpenShareForm(file)}>Share</button>
                            <button onClick={() => handleDownloadFile(file.uuid, file.name)}>Download</button>
                            <button onClick={() => handleViewFile(file.uuid)}>View</button>
                        </li>
                    ))}
                </ul>
            ) : (
                <p>No files found.</p>
            )}

            <h2>Shared with You</h2>
            {sharedFiles.length > 0 ? (
                <ul>
                    {sharedFiles.map((file) => (
                        <li key={file.id} style={{ marginBottom: '20px' }}>
                            <h4>{file.name}</h4>
                            <p>Shared by: {file.owner}</p>
                            {file.permission === 'view' && (
                                <button onClick={() => handleViewFile(file.id)}>View</button>
                            )}
                            {file.permission === 'download' && (
                                <>
                                    <button onClick={() => handleViewFile(file.id)}>View</button>
                                    <button onClick={() => handleDownloadFile(file.id, file.name)}>Download</button>
                                </>
                            )}
                        </li>
                    ))}
                </ul>
            ) : (
                <p>No files shared with you.</p>
            )}

            {previewFile && (
                <div style={{ border: '1px solid #ccc', padding: '20px', marginTop: '20px' }}>
                    <h3>File Preview</h3>
                    <button onClick={() => setPreviewFile(null)}>Close Preview</button>
                    {previewFile.type === 'image' ? (
                        <img
                            src={previewFile.url}
                            alt="Preview of uploaded file" // Describe what the image represents
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


            {isSharing && (
                <div style={{ border: '1px solid #ccc', padding: '20px', marginTop: '20px' }}>
                    <h3>Share File: {selectedFile.name}</h3>
                    <label>
                        Search User:
                        <input
                            type="text"
                            placeholder="Enter username"
                            value={searchQuery}
                            onChange={(e) => {
                                setSearchQuery(e.target.value);
                                handleSearchUsers(e.target.value);
                            }}
                        />
                    </label>
                    {searchResults.length > 0 && (
                        <ul>
                            {searchResults.map((user) => (
                                <li
                                    key={user.id}
                                    onClick={() => setSelectedUser(user.id)}
                                    style={{
                                        cursor: 'pointer',
                                        background: selectedUser === user.id ? '#e0e0e0' : 'white',
                                    }}
                                >
                                    {user.username}
                                </li>
                            ))}
                        </ul>
                    )}
                    <label>
                        Permission:
                        <select
                            value={permission}
                            onChange={(e) => setPermission(e.target.value)}
                        >
                            <option value="view">View</option>
                            <option value="download">Download</option>
                        </select>
                    </label>
                    <label>
                        Expiry (minutes):
                        <input
                            type="number"
                            value={expiry}
                            onChange={(e) => setExpiry(e.target.value)}
                        />
                    </label>
                    <br />
                    <button onClick={handleShareWithUsers}>Share File</button>
                    <button onClick={() => setIsSharing(false)}>Cancel</button>
                    {generatedLink && (
                        <div>
                            <p>Secure Link:</p>
                            <input
                                type="text"
                                value={generatedLink}
                                readOnly
                                style={{ width: '100%' }}
                            />
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default FileList;
