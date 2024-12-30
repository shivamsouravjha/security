import apiClient from './apiClient';

export const base64ToUint8Array = (base64String) => {
    const binaryString = atob(base64String);
    const binaryLength = binaryString.length;
    const bytes = new Uint8Array(binaryLength);
    for (let i = 0; i < binaryLength; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
};

export const handleViewFile = async (setPreviewFile,fileId) => {
    try {
      const response = await apiClient.get(`https://localhost:8000/api/files/${fileId}/download/`, {
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
      console.log('Failed to view the file. Please try again.', error);
    }
  };
export const fetchAndDecryptFile = async (setDecryptedBlob, setOriginalFilename, setLoading, setRole, setError, token) => {
    try {
        // Fetch metadata for the encrypted file
        const response = await apiClient.get(`https://localhost:8000/api/files/access/${token}/`, {
            responseType: 'json',
        });

        const { partially_decrypted_file, client_key, client_iv, original_filename, role } = response.data;
        const parsedKey = JSON.parse(client_key); // Parse the key
        const parsedIV = JSON.parse(client_iv); // Parse the IV
        const encryptedFileBuffer = base64ToUint8Array(partially_decrypted_file);
        const decryptedFile = await decryptFile(encryptedFileBuffer, parsedKey, parsedIV);
        setDecryptedBlob(new Blob([new Uint8Array(decryptedFile)]));
        setOriginalFilename(original_filename);
        setLoading(false);
        setRole(role);
    } catch (err) {
        console.error("Decryption Process Failed:", err);
        setError("Failed to fetch or decrypt the file.");
        setLoading(false);
    }
};

export async function decryptFile(encryptedFile, encryptionKey, iv) {
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

export const handleDownloadFile = async (fileId, fileName, setError) => {
    try {
        const response = await apiClient.get(`https://localhost:8000/api/files/${fileId}/download/`, {
            withCredentials: true,
            responseType: 'json',
        });
        const { partially_decrypted_file, client_key, client_iv, original_filename } = response.data;
        const parsedKey = JSON.parse(client_key); // Parse the key
        const parsedIV = JSON.parse(client_iv); // Parse the IV
        const encryptedFileBuffer = base64ToUint8Array(partially_decrypted_file);
        const decryptedFile = await decryptFile(encryptedFileBuffer, parsedKey, parsedIV); // Assume decryptFile is imported or defined elsewhere
        const url = window.URL.createObjectURL(new Blob([new Uint8Array(decryptedFile)]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', original_filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        setError && setError('Failed to download the file. Please try again.');
    }
};
