const crypto = require('crypto');

// Fungsi untuk mengukur waktu eksekusi
function measureExecutionTime(label, fn) {
    console.time(label);
    fn();
    console.timeEnd(label);
}

// Fungsi Enkripsi dan Dekripsi AES (Simetris)
function aesEncryptDecrypt() {
    const key = crypto.randomBytes(32); // Kunci 256-bit
    const iv = crypto.randomBytes(16);  // Inisialisasi vektor (IV)
    const data = "This is a test message for AES encryption"; // Data untuk dienkripsi

    // Enkripsi
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Dekripsi
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Menampilkan hasil
    console.log('AES Encrypted:', encrypted);
    console.log('AES Decrypted:', decrypted);
}

// Fungsi Enkripsi dan Dekripsi RSA (Asimetris)
function rsaEncryptDecrypt() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Panjang kunci
    });

    const data = "This is a test message for RSA encryption"; // Data untuk dienkripsi

    // Enkripsi
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data));

    // Dekripsi
    const decrypted = crypto.privateDecrypt(privateKey, encrypted);

    // Menampilkan hasil
    console.log('RSA Encrypted:', encrypted.toString('hex'));
    console.log('RSA Decrypted:', decrypted.toString('utf8'));
}

// Pengukuran waktu eksekusi untuk AES
measureExecutionTime('AES Encryption/Decryption', aesEncryptDecrypt);

// Pengukuran waktu eksekusi untuk RSA
measureExecutionTime('RSA Encryption/Decryption', rsaEncryptDecrypt);
