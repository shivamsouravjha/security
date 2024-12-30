import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';

const EnableMFA = () => {
    const [totpSecret, setTotpSecret] = useState('');
    const [qrCode, setQrCode] = useState('');
    const [totpCode, setTotpCode] = useState('');
    const navigate = useNavigate();
    const location = useLocation();
    const hexToBase64 = (hexString) => {
        const binary = hexString
            .match(/.{1,2}/g) // Split hex string into pairs of characters
            .map((byte) => String.fromCharCode(parseInt(byte, 16))) // Convert to binary
            .join('');
        return btoa(binary); // Convert binary to Base64
    };
    // Extract username and password passed from login page
    const { username, password } = location.state || {};

    if (!username || !password) {
        alert('Invalid access. Redirecting to login.');
        navigate('/login'); // Redirect if credentials are missing
    }

    const generateTotpSecret = async () => {
        try {
            const response = await axios.post(
                'https://localhost:8000/api/mfa/generate-secret/',
                { username, password }, // Include username and password
                { withCredentials: true }
            );
            setTotpSecret(response.data.totp_secret);
            setQrCode(response.data.qr_code);
        } catch (error) {
            console.error('Failed to generate TOTP secret:', error.response ? error.response.data : error.message);
        }
    };

    const enableMfa = async () => {
        try {
            await axios.post(
                'https://localhost:8000/api/mfa/enable/',
                { username, password, totp_secret: totpSecret, totp_code: totpCode }, // Include username and password
                {
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    withCredentials: true,
                }
            );
            alert('MFA enabled successfully!');
            navigate('/login');
        } catch (error) {
            console.error('Failed to enable MFA:', error.response ? error.response.data : error.message);
        }
    };

    return (
        <div>
            <h1>Enable MFA</h1>
            {!totpSecret ? (
                <button onClick={generateTotpSecret}>Generate TOTP Secret</button>
            ) : (
                <div>
                    <p>Scan this QR code with your authenticator app:</p>
                    <img
                        src={`data:image/png;base64,${hexToBase64(qrCode)}`}
                        alt="TOTP QR Code"
                    />
                    <p>Or manually enter this secret: <strong>{totpSecret}</strong></p>
                    <div>
                        <label>Enter TOTP Code:</label>
                        <input
                            type="text"
                            value={totpCode}
                            onChange={(e) => setTotpCode(e.target.value)}
                            required
                        />
                    </div>
                    <button onClick={enableMfa}>Enable MFA</button>
                </div>
            )}
        </div>
    );
};

export default EnableMFA;
