#pragma warning disable CS1591
using System.Text.Json.Serialization;

namespace Solnet.KeyStore.Model
{
    public class CipherParams
    {
        public CipherParams()
        {
        }

        public CipherParams(byte[] nonce)
        {
            Nonce = nonce.ToHex();
        }

        [JsonPropertyName("nonce")]
        // ReSharper disable once MemberCanBePrivate.Global
        public string Nonce { get; init; }
    }
}