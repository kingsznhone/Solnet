#pragma warning disable CS1591

using System.Text.Json.Serialization;

namespace Solnet.KeyStore.Model
{
    public class CryptoInfo<TKdfParams> where TKdfParams : KdfParams
    {
        public CryptoInfo()
        {
        }

        public CryptoInfo(string cipher, byte[] cipherText, byte[] iv, byte[] mac, byte[] salt, TKdfParams kdfParams,
            string kdfType)
        {
            Cipher = cipher;
            CipherText = cipherText.ToHex();
            Mac = mac.ToHex();
            CipherParams = new CipherParams(iv);
            Kdfparams = kdfParams;
            Kdfparams.Salt = salt.ToHex();
            Kdf = kdfType;
        }

        [JsonPropertyName("cipher")]
        public string Cipher { get; }

        [JsonPropertyName("ciphertext")]
        public string CipherText { get; init; }

        // ReSharper disable once StringLiteralTypo
        [JsonPropertyName("cipherparams")]
        public CipherParams CipherParams { get; init; }

        [JsonPropertyName("kdf")]
        public string Kdf { get; }

        [JsonPropertyName("mac")]
        public string Mac { get; init; }

        // ReSharper disable once StringLiteralTypo
        [JsonPropertyName("kdfparams")]
        public TKdfParams Kdfparams { get; init; }
    }
}