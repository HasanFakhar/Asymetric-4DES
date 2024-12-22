// Store the unique ID returned from the /encrypt endpoint
let currentID = '';

const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const tamperBtn  = document.getElementById('tamperBtn');

encryptBtn.addEventListener('click', () => {
  const plaintext = document.getElementById('plaintext').value;

  // Call your Python backend /encrypt endpoint
  fetch('http://127.0.0.1:5000/encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext })
  })
    .then(response => response.json())
    .then(data => {
      // data should contain 'id' and 'ciphertext'
      currentID = data.id;
      document.getElementById('ciphertext').value = data.ciphertext;
      console.log("Unique ID stored:", currentID);
    })
    .catch(err => {
      console.error("Encryption error:", err);
      alert("Encryption failed. See console for details.");
    });
});

decryptBtn.addEventListener('click', () => {
  const ciphertext = document.getElementById('ciphertext').value;

  // Call your Python backend /decrypt endpoint
  fetch('http://127.0.0.1:5000/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: currentID,
      ciphertext: ciphertext
    })
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        console.error(data.error);
        alert("Decryption failed: " + data.error);
      } else {
        document.getElementById('decrypted').value = data.plaintext;
      }
    })
    .catch(err => {
      console.error("Decryption error:", err);
      alert("Decryption failed. See console for details.");
    });
});

// "Tamper" will flip some bits in the ciphertext
tamperBtn.addEventListener('click', () => {
  const ciphertextArea = document.getElementById('ciphertext');
  let currentCiphertext = ciphertextArea.value;

  if (!currentCiphertext) {
    alert("No ciphertext found to tamper with!");
    return;
  }

  // Example tampering: Change the first character's ASCII code
  // or slice off a small chunk - anything that modifies the string.
  // Here we just flip some bits in the first 4 characters.

  // Convert from base64 string to a Uint8Array of bytes
  // (assuming your ciphertext is base64-encoded)
  let rawBytes = atob(currentCiphertext); 

  // Convert from string to an array of char codes
  let charArray = rawBytes.split('').map(c => c.charCodeAt(0));

  // Flip bits in the first byte for demonstration
  // For example, XOR it with 0xFF
  if (charArray.length > 0) {
    charArray[0] = charArray[0] ^ 0xFF; 
  }

  // Rebuild the tampered string
  let tamperedString = String.fromCharCode(...charArray);

  // Convert back to base64
  let tamperedBase64 = btoa(tamperedString);

  ciphertextArea.value = tamperedBase64;
  alert("Ciphertext has been tampered with!");
});
