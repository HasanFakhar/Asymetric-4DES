// In a real application, you'd replace the "fetch" URLs with the
// actual endpoints your Python server exposes (e.g., /encrypt, /decrypt).
let currentID = ''
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');

encryptBtn.addEventListener('click', () => {
  const plaintext = document.getElementById('plaintext').value;

  // Example fetch to Python backend (Flask/FastAPI/other):
  // Assumes your server has an /encrypt endpoint that
  // accepts JSON { plaintext: "..." } and returns JSON { ciphertext: "..." }.
  fetch('http://127.0.0.1:5000/encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ plaintext })
  })
    .then(response => response.json())
    .then(data => {
      // data.ciphertext is expected from your backend
      currentID = data.id
      console.log(currentID)
      document.getElementById('ciphertext').value = data.ciphertext || '';
    
    })
    .catch(err => {
      console.error('Encryption error:', err);
      alert('Encryption failed. Check console for details.');
    });
});

decryptBtn.addEventListener('click', () => {
  const ciphertext = document.getElementById('ciphertext').value;
  console.log(currentID)
 
  // Example fetch to Python backend:
  // Expects JSON { ciphertext: "..." } and returns JSON { plaintext: "..." }.
  fetch('http://127.0.0.1:5000/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
        id: currentID,     // MUST pass the stored ID!
        ciphertext: ciphertext
    })
  })
    .then(response => response.json())
    .then(data => {
      // data.plaintext is expected from your backend
      document.getElementById('decrypted').value = data.plaintext || '';
    })
    .catch(err => {
      console.error('Decryption error:', err);
      alert('Decryption failed. Check console for details.');
    });
});
