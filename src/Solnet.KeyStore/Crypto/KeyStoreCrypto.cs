#pragma warning disable CS1591

//using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Solnet.KeyStore.Crypto
{
    //https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
    public class KeyStoreCrypto
    {
        public byte[] GenerateDerivedScryptKey(byte[] password, byte[] salt, int n, int r, int p, int dkLen, bool checkRandN = false)
        {
            if (checkRandN)
            {
                if (r == 1 && n >= 65536)
                {
                    throw new ArgumentException("Cost parameter N must be > 1 and < 65536.");
                }
            }

            return Scrypt.CryptoScrypt(password, salt, n, r, p, dkLen);
        }

        public byte[] GenerateCipherKey(byte[] derivedKey)
        {
            var cypherKey = new byte[16];
            Array.Copy(derivedKey, cypherKey, 16);
            return cypherKey;
        }

        public byte[] CalculateKeccakHash(byte[] value)
        {
            using SHA3_256 sha3 = SHA3_256.Create();
            return sha3.ComputeHash(value);
        }

        public byte[] GenerateMac(byte[] derivedKey, byte[] cipherText)
        {
            var result = new byte[16 + cipherText.Length];
            Array.Copy(derivedKey, 16, result, 0, 16);
            Array.Copy(cipherText, 0, result, 16, cipherText.Length);
            return CalculateKeccakHash(result);
        }

        public byte[] GeneratePbkdf2Sha256DerivedKey(string password, byte[] salt, int count, int dklen)
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                count,
                HashAlgorithmName.SHA256,
                dklen
            );
        }

        public static (byte[] Ciphertext, byte[] Tag) GenerateAesGcmCipher(byte[] nonce, byte[] key, byte[] plaintext)
        {
            // GCM tag length 16 bytes£¨128bit£©
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            return (ciphertext, tag);
        }

        public static byte[] DecryptAesGcmCipher(byte[] nonce, byte[] key, byte[] ciphertext, byte[] tag)
        {
            byte[] plaintext = new byte[ciphertext.Length];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

            return plaintext;
        }

        public byte[] DecryptScrypt(string password, byte[] mac, byte[] nonce, byte[] cipherText, int n, int p, int r,
            byte[] salt, int dklen)
        {
            var derivedKey = GenerateDerivedScryptKey(GetPasswordAsBytes(password), salt, n, r, p, dklen, false);
            return Decrypt(mac, nonce, cipherText, derivedKey);
        }

        public byte[] DecryptPbkdf2Sha256(string password, byte[] mac, byte[] nonce, byte[] cipherText, int count, byte[] salt,
            int dklen)
        {
            var derivedKey = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                count,
                HashAlgorithmName.SHA256,
                dklen
            );
            return Decrypt(mac, nonce, cipherText, derivedKey);
        }

        public byte[] Decrypt(byte[] mac, byte[] nonce, byte[] cipherText, byte[] derivedKey)
        {
            var encryptKey = new byte[16];
            Array.Copy(derivedKey, encryptKey, 16);

            var privateKey = DecryptAesGcmCipher(nonce, encryptKey, cipherText, mac);

            return privateKey;
        }

        public byte[] GetPasswordAsBytes(string password)
        {
            return Encoding.UTF8.GetBytes(password);
        }
    }
}