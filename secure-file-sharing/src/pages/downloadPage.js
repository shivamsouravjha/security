import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchAndDecryptFile } from '../utils/fileUtils';

function DownloadPage() {
    const { token } = useParams(); // Extract the token from the URL
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [decryptedBlob, setDecryptedBlob] = useState(null);
    const [role, setRole] = useState(null);
    const [originalFilename, setOriginalFilename] = useState("");

    useEffect(() => {
        async function fetchData() {
            await fetchAndDecryptFile(setDecryptedBlob, setOriginalFilename, setLoading, setRole, setError, token);
        }
        fetchData()
    }, [token]);

    const handleDownload = () => {
        if (decryptedBlob) {
            const url = window.URL.createObjectURL(decryptedBlob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', originalFilename);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
    };

    if (loading) {
        return <p>Downloading and decrypting your file...</p>;
    }

    if (error) {
        return <p>Error: {error}</p>;
    }

    return (
        <div>
            <h1>File Preview</h1>
            {decryptedBlob ? (
                <div>
                    {/* Display preview based on the file type */}
                    {originalFilename.endsWith(".jpg") ||
                        originalFilename.endsWith(".jpeg") ||
                        originalFilename.endsWith(".png") ||
                        originalFilename.endsWith(".gif") ? (
                        <img
                            src={URL.createObjectURL(decryptedBlob)}
                            alt="Preview"
                            style={{ maxWidth: "100%", height: "auto" }}
                        />
                    ) : originalFilename.endsWith(".txt") ? (
                        <iframe
                            src={URL.createObjectURL(decryptedBlob)}
                            title="Text File Preview"
                            style={{ width: "100%", height: "500px", border: "none" }}
                        ></iframe>
                    ) : (
                        <p>Preview not available for this file type.</p>
                    )}

                    {role === "owner" || role === "download" ? (
                        <button onClick={handleDownload}>Download File</button>
                    ) : (
                        <p>You do not have permission to download this file.</p>
                    )}
                </div>
            ) : (
                <p>Preview not available.</p>
            )}
        </div>
    );
}

export default DownloadPage;
