// TEST FILE - Node.js crypto usage patterns
const crypto = require('crypto');
const JWT_SECRET = 'ci-test-jwt-secret-do-not-use';              // WEAK: hardcoded
crypto.createHash('md5').update('x').digest('hex');              // WEAK
crypto.createHash('sha512').update('x').digest('hex');
crypto.createCipheriv('aes-128-ecb', Buffer.alloc(16), null);    // WEAK: ECB
crypto.createCipheriv('aes-256-gcm', crypto.randomBytes(32), crypto.randomBytes(12));
crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });      // WEAK
crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
crypto.generateKeyPairSync('ed25519');
crypto.createHmac('sha256', JWT_SECRET).update('x').digest();
crypto.pbkdf2Sync('pw', 'salt', 1000, 32, 'sha1');               // WEAK: low iterations + SHA1
const https = require('https');
new https.Agent({ rejectUnauthorized: false, minVersion: 'TLSv1' }); // WEAK
