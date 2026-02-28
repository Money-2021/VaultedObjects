using SqlServer.Providers;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace UnitTestVaultedObjects
{
    public class Support
    {
        public static Guid MaxValue = new Guid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
        public static string VaultMe(string userTokenPath)
        {
            FidoProvider fp = FidoProvider.GetProvider(userTokenPath);
            // Extract endpoint from Device Token
            Uri _baseUri = new Uri(fp.Audience());

            // Obtain Function JwToken
            HttpClient _httpClient = new HttpClient();
            // Build funtion endpoint Uri
            string _relativeUrl = "User/VaultMe";
            Uri _uri = new Uri(_baseUri, _relativeUrl);
            _httpClient.BaseAddress = _baseUri;
            // Add Device Jwtoken
            _httpClient.DefaultRequestHeaders.Add("x-token", fp.JwToken());
            // Add device signature
            byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(fp.JwToken()));
            byte[] signature = fp.SignHash(hashBytes);
            _httpClient.DefaultRequestHeaders.Add("x-jws-signature", Convert.ToBase64String(signature));
            // Get response
            HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
            if (response.IsSuccessStatusCode)
            {

                Stream receiveStream = response.Content.ReadAsStream();
                StreamReader reader = new StreamReader(receiveStream, Encoding.UTF8);
                string jwToken = reader.ReadToEnd();
                return jwToken;
            }
            else
            {
                // fail
                string error = response.Content.ReadAsStringAsync().Result;
                if (string.IsNullOrEmpty(error))
                {
                    error = response.ReasonPhrase;
                }
                throw new Exception(error);
            }

        }
        public static Guid AddObject(FidoProvider fp, string vaultMeToken, byte[] objectbytes, string objInfo)
        {
            /* Azure By default, limits the HTTP POST size to approximately 28.6 MB.
             * The HTTP protocol itself does not impose a size limit on POST requests, 
             * but web servers and applications set these limits to prevent denial-of-service attacks and manage resources.
             * The Vaulted Object application set the size limit dynamically, via the VaultMe token; but is never less than 10 MB.
             */
            if (objectbytes.Length > UserToken.ExtractSize(vaultMeToken))
            {
                throw new Exception("Exceeded Size limit of " + UserToken.ExtractSize(vaultMeToken) + " MB.");
            }

            Uri _baseUri = new Uri(FidoProvider.ExtractAudience(vaultMeToken));
            // Obtain Function JwToken
            HttpClient _httpClient = new HttpClient();
            // Build funtion endpoint Uri
            string _relativeUrl = "Object/Add";
            Uri _uri = new Uri(_baseUri, _relativeUrl);
            _httpClient.BaseAddress = _baseUri;
            // Add VaultMe Jwtoken
            _httpClient.DefaultRequestHeaders.Add("x-token", vaultMeToken);
            // Extract other public key
            string _ejwk = FidoProvider.ExtractJwk(vaultMeToken);
            Guid _jti = FidoProvider.ExtractJti(vaultMeToken);
                      
            // Encrypt Object 
            Dictionary<string, byte[]> dict = fp.EncryptObject(objectbytes, _jti, _ejwk);
            byte[] pdata = dict["ciphertext"];
             
            // Add protectedVaulted object content to Post 
            ByteArrayContent content = new ByteArrayContent(pdata);

            _httpClient.DefaultRequestHeaders.Add("x-jws-object", objInfo);
            // Get Vaulted Object Identifier response
            HttpResponseMessage response = _httpClient.PostAsync(_uri, content).Result;
            if (response.IsSuccessStatusCode)
            {
                // GUID
                string onjectId = response.Content.ReadAsStringAsync().Result;
                // Need to store this GUID with mapping to orignal file for retrieval.
                return new Guid(onjectId);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                return MaxValue; // max Guid value
            }
            else
            {
                // fail
                string error = response.Content.ReadAsStringAsync().Result;
                if (string.IsNullOrEmpty(error))
                {
                    error = response.ReasonPhrase;
                }
                throw new Exception(error);
            }
            return Guid.Empty;
        }
    }
    public class ObjectToken
    {
        public string SecureIdentity { get; set; }
        public string FileName { get; set; }
        public DateTime? FileDate { get; set; }
        public Guid? ObjectId { get; set; }
        public byte[] ObjectHash { get; set; }
        public long Counter { get; set; }
        public string Jwk { get; set; }
        public bool Verified { get; set; }

        public ObjectToken()
        {
            Verified = false;
        }

        public static ObjectToken VerifyObjectToken(string json)
        {
            ObjectToken sign = DecodeObject(json);
            sign.Verified = JwtProvider.ValidateJwToken(json); // Validate Signature JWToken contents.
            return sign;
        }
        public static string Encode(FidoProvider fp, byte[] objectBytes, string filename, string jwk, byte[] pkey, Guid? objectId, DateTime? filedate = null)
        {
            byte[] hashBytes = Shake256.HashData(objectBytes, 64); // Quantum safe for long term verification of object storage 
                                                                   // Serialise Header
            MemoryStream ms = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("alg");
                writer.WriteStringValue("Ed25519");
                writer.WritePropertyName("typ");
                writer.WriteStringValue("JWT");
                writer.WriteEndObject();

            }
            string encodedJwEHeader = Base64Url.Encode(ms.ToArray());
            string encodedHash = Convert.ToBase64String(hashBytes);

            // serialise Payload
            ms = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("Type");
                writer.WriteStringValue("ObjectInfo"); // Object Meta data, peper One Cipher encrypted object is inside Post
                writer.WritePropertyName("SecureIdentity");
                writer.WriteStringValue(fp.SecureIdentity());
                writer.WritePropertyName("DeviceIdentity");
                writer.WriteStringValue(fp.DeviceSin());
                writer.WritePropertyName("Filename");
                writer.WriteStringValue(filename);
                if (string.IsNullOrEmpty(jwk) == false)
                {
                    writer.WritePropertyName("Jwk");
                    writer.WriteStringValue(jwk);
                    writer.WritePropertyName("WKey");
                    writer.WriteStringValue(Convert.ToBase64String(pkey));
                }
                if (filedate.HasValue)
                {
                    DateTime src = filedate.Value;
                    writer.WritePropertyName("Filedate");
                    writer.WriteStringValue(new DateTime(src.Year, src.Month, src.Day, src.Hour, 0, 0)); // remove min and sec
                }
                if (objectId.HasValue)
                {
                    writer.WritePropertyName("ObjectId");
                    writer.WriteStringValue(objectId.ToString());
                }
                writer.WritePropertyName("objectHash");
                writer.WriteStringValue(encodedHash);
                writer.WritePropertyName("counter");
                writer.WriteNumberValue(fp.Counter());
                writer.WriteEndObject();

            }
            string encodedPayload = Base64Url.Encode(ms.ToArray());
            byte[] sigBytes = Encoding.UTF8.GetBytes(encodedJwEHeader + "." + encodedPayload);
            byte[] sig = fp.SignHash(sigBytes);
            string encodedJWESignature = Base64Url.Encode(sig);
            return encodedJwEHeader + "." + encodedPayload + "." + encodedJWESignature;
        }

        public class Vaulted
        {
            public Guid ObjectId { get; set; }
            public string ObjectInfo { get; set; }
            public string Jwk { get; set; } // VaultMe->Public Key
            public DateTime TimeStamp { get; set; }
            public Uri Download { get; set; }

            public async Task<byte[]?> GetUrlContent()
            {
                using (var client = new HttpClient())
                using (var result = await client.GetAsync(Download.AbsoluteUri))
                return result.IsSuccessStatusCode ? await result.Content.ReadAsByteArrayAsync() : null;
            }
        }

        public static Vaulted DecodeVaulted(string json)
        {
             var _payload = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            // Decode Vaulted Object
            Vaulted vo = new Vaulted();
            foreach (KeyValuePair<string, object> kvp in _payload)
            {
                string key = kvp.Key.ToLower();
                object value = kvp.Value;
                switch (key.ToLower())
                {
                    case "objectinfo":
                        vo.ObjectInfo = value.ToString();
                        break;
                    case "jwk":
                        vo.Jwk = value.ToString();
                        break;
                    case "objectid":
                        vo.ObjectId = new Guid(value.ToString());
                        break;
                    case "uri":
                        vo.Download = new Uri(value.ToString());
                        break;
                }

            }
            return vo;
        }
        private static ObjectToken DecodeObject(string json)
        {
            string content = json.Split('.')[1]; // second segment
            var jsonpayload = Base64Url.Decode(content);
            var _payload = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonpayload);
            // Decode Signtaure
            ObjectToken sig = new ObjectToken();
            foreach (KeyValuePair<string, object> kvp in _payload)
            {
                string key = kvp.Key.ToLower();
                object value = kvp.Value;
                switch (key.ToLower())
                {
                    case "secureidentity":
                        sig.SecureIdentity = value.ToString();
                        break;
                    case "counter":
                        sig.Counter = long.Parse(value.ToString());
                        break;
                    case "jwk":
                        sig.Jwk = value.ToString();
                        break;
                    case "filename":
                        sig.FileName = value.ToString();
                        break;
                    case "objectid":
                        sig.ObjectId = new Guid(value.ToString());
                        break;
                    case "filedate":
                        DateTime fDateTime;
                        DateTime.TryParse(value.ToString(), out fDateTime);
                        sig.FileDate = fDateTime;
                        break;
                    case "objecthash":
                        sig.ObjectHash = Base64Url.Decode(value.ToString());
                        break;

                }

            }
            sig.Verified = JwtProvider.ValidateJwToken(json);
            return sig;

        }

    }
}
