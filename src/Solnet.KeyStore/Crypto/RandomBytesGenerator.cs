#pragma warning disable CS1591

using System.Security.Cryptography;

namespace Solnet.KeyStore.Crypto
{
    public class RandomBytesGenerator : IRandomBytesGenerator
    {
        private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();

        public byte[] GenerateRandomAesGcmNonce()
        {
            return GenerateRandomBytes(12);
        }

        public byte[] GenerateRandomSalt()
        {
            return GenerateRandomBytes(32);
        }

        private static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            Random.GetBytes(bytes);
            return bytes;
        }
    }
}