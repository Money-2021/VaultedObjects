using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public class FidoProvider
{
    // Supporting Objects
    public class Base64Url
    {
        public static string Encode(byte[] input)
        {
            return Convert.ToBase64String(input).Split('=')[0].Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Decode(string input)
        {
            string text = input;
            text = text.Replace('-', '+'); // 62nd char of encoding
            text = text.Replace('_', '/'); // 63rd char of encoding
            switch (text.Length % 4) // Pad with trailing '='s
            {
                case 2: // Two pad chars
                    text += "==";
                    break;
                case 3: // One pad char
                    text += "=";
                    break;
                case 0: // No pad chars in this case
                    break;
                default:
                    throw new ArgumentOutOfRangeException("input", "Illegal base64url string!");

            }

            return Convert.FromBase64String(text);
        }
    }
    public class DeviceStore 
    {
        public string SecureIdentity { get; set; }      // Secure Identity
        public byte[] KeyHandle { get; set; }           // Registration Key Handle 
        public string JwKey { get; set; }               // Device Ed25519 Public Key
        public long Counter { get; set; }                 // Cik (32 bit signed integer)
        public string JwToken { get; set; }             // User JWToken
        public byte[] ProtectedDeviceKey { get; set; }
        public string DeviceSin { get; set; }           // Device Secure Identity

        public DeviceStore()
        {

        }
     
        public string ToJason()
        {

            MemoryStream ms = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("SecureIdentity");
                writer.WriteStringValue(SecureIdentity);
                writer.WritePropertyName("DeviceSin");
                writer.WriteStringValue(DeviceSin);
                writer.WritePropertyName("JwKey");
                writer.WriteStringValue(JwKey);
                writer.WritePropertyName("JwToken");
                writer.WriteStringValue(JwToken);
                writer.WritePropertyName("KeyHandle");
                writer.WriteStringValue(Convert.ToBase64String(KeyHandle));
                writer.WritePropertyName("ProtectedDeviceKey");
                writer.WriteStringValue(Convert.ToBase64String(ProtectedDeviceKey));
                writer.WriteEndObject();

            }
            return Encoding.UTF8.GetString(ms.ToArray());

        }
        public DeviceStore(string json)
        {
            // Parse json
            var options = new JsonReaderOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip
            };
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), options);
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                    case JsonTokenType.String:

                        string text = reader.GetString();
                        switch (text)
                        {

                            case "SecureIdentity":
                                SecureIdentity = text;
                                break;
                            case "DeviceSin":
                                DeviceSin = text;
                                break;
                            case "KeyHandle":
                                KeyHandle = Convert.FromBase64String(text);
                                break;
                            case "ProtectedDeviceKey":
                                ProtectedDeviceKey = Convert.FromBase64String(text);
                                break;
                            case "Counter":
                                Counter = Convert.ToInt32(text);
                                break;
                            case "JwKey":
                                JwKey = text;
                                break;
                            case "JwToken":
                                JwToken = text;
                                break;
                        }
                        break;

                }
            }
        }
    }

    private Edward25519.KeyPair _kp;
    private string _audience;
    DeviceStore ds;
   
  
    public FidoProvider(string sin, byte[] pDevicekey)
    {

        ds = new DeviceStore();
        ds.ProtectedDeviceKey = pDevicekey;
        ds.SecureIdentity = sin;
    
    }
    public FidoProvider(DeviceStore device)
    {
        ds = device;
        byte[] _key = DeriveKey(device.KeyHandle);
        _kp = Edward25519.Ed25519.GenerateKeyPair(_key);
        _audience = ExtractAudience(device.JwToken);
    }
    public FidoProvider(string sin, byte[] pDevicekey, byte[] keyHandle)
    {
        ds = new DeviceStore();
        ds.SecureIdentity = sin;
        // Derive Key
        byte[] _key = DeriveKey(keyHandle);
        _kp = Edward25519.Ed25519.GenerateKeyPair(_key);
        ds.DeviceSin = DeviceIdentity(_kp.PublicKey);
    }
    public static FidoProvider GetProvider(string path)
    {
        DeviceStore store = GetStore(path);
        FidoProvider p = new FidoProvider(store);
        return p;
    }
    public int ExtractSize(string token)
    {
        string content = token.Split('.')[1]; // second segment
        var jsonPayload = Base64Url.Decode(content);
        var payLoad = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonPayload);
        Dictionary<string, string> claims = payLoad.ToDictionary(k => k.Key, k => k.Value == null ? "" : k.Value.ToString());
        string skey = claims.FirstOrDefault(x => x.Key == "size").Value;
        if (string.IsNullOrEmpty(skey))
        {
            return 10000; // 10 Meg default
        }
        return Convert.ToInt32(skey);
    }
   
    public Guid GetGuid()
    {
        byte[] rnd = RandomNumberGenerator.GetBytes(16);
        return new Guid(rnd);
    }
    public byte[] LongToBytes(long value)
    {
        ulong _value = (ulong)value;

        return BitConverter.IsLittleEndian
            ? new[] { (byte)((_value >> 56) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)(_value & 0xFF) }
            : new[] { (byte)(_value & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 56) & 0xFF) };
    }
    public static string ExtractAudience(string token)
    {
        string content = token.Split('.')[1]; // second segment
        var jsonPayload = Base64Url.Decode(content);
        var payLoad = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonPayload);
        Dictionary<string, string> claims = payLoad.ToDictionary(k => k.Key, k => k.Value == null ? "" : k.Value.ToString());
        string skey = claims.FirstOrDefault(x => x.Key == "aud").Value;
        return skey;
    }
    public static string ExtractJwk(string token)
    {
        string content = token.Split('.')[1]; // second segment
        var jsonPayload = Base64Url.Decode(content);
        var payLoad = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonPayload);
        Dictionary<string, string> claims = payLoad.ToDictionary(k => k.Key, k => k.Value == null ? "" : k.Value.ToString());
        string skey = claims.FirstOrDefault(x => x.Key == "Jwk").Value;

        return skey;
    }
    public static Guid ExtractJti(string token)
    {
        string content = token.Split('.')[1]; // second segment
        var jsonPayload = Base64Url.Decode(content);
        var payLoad = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(jsonPayload);
        Dictionary<string, string> claims = payLoad.ToDictionary(k => k.Key, k => k.Value == null ? "" : k.Value.ToString());
        string sjti = claims.FirstOrDefault(x => x.Key.ToLower() == "jti").Value;
        return new Guid(sjti);
    }
   
    public string Audience()
    {
        return _audience;
    }
    public string GetJwToken()
    {
        return ds.JwToken;
    }
    public string GetSecureIdentity()
    {
        return ds.SecureIdentity;
    }
    public string GetDeviceSin()
    {
        return ds.DeviceSin;
    }
    public long GetCounter()
    {
        return ds.Counter;
    }
    private static byte[] Protect(byte[] share)
    {

        byte[] encBytes = ProtectedData.Protect(share, null, DataProtectionScope.CurrentUser);
        return encBytes;
    }
    private static byte[] UnProtect(byte[] share)
    {

        byte[] pBytes = ProtectedData.Unprotect(share, null, DataProtectionScope.CurrentUser);
        return pBytes;
    }
    private static bool ByteArraysEqual(byte[] a1, byte[] a2)
    {
        return StructuralComparisons.StructuralEqualityComparer.Equals(a1, a2);
    }
    public static DeviceStore GetStore(string storePath)
    {
        string sToken = System.IO.File.ReadAllText(storePath);
        DeviceStore store = JsonSerializer.Deserialize<DeviceStore>(sToken);
        // Check expire exp
        bool isExpired = CheckExpired(store.JwToken);
        if (isExpired)
        {
            RecoveryResponse r = TokenRefresh(store.JwToken);
            // Update Device Token
            store.JwToken = r.jwToken;
            store.Counter = r.counter;
            // Save DeviceStore
            SaveStore(storePath, store);
        }

        return store;
    }

    public class RecoveryResponse
    {
        public RecoveryResponse()
        {
        }
        public RecoveryResponse(bool protect = false)
        {
            isProtected = protect;
        }
        public long counter { get; set; }
        public byte[] share { get; set; }
        public string jwToken { get; set; }
        public bool? isProtected { get; set; } //  encrypted setupcode
    }
    private static RecoveryResponse TokenRefresh(string jwToken)
    {
      
        // Extract Function endpoint from User Token
        var securityToken = new JwtSecurityToken(jwToken);
        var claim = securityToken.Claims.FirstOrDefault(x => x.Type == "SecureIdentity");
        string _secureIdentity = claim.Value;
        claim = securityToken.Claims.FirstOrDefault(x => x.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti);
        string _jti = claim.Value;
        Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
        // Obtain Function JwToken
        HttpClient _httpClient = new HttpClient();
        // Build funtion endpoint Uri
        string _relativeUrl = "User/Refresh";
        Uri _uri = new Uri(_baseUri, _relativeUrl);
        _httpClient.BaseAddress = _baseUri;
        // Add User Jwtoken
        _httpClient.DefaultRequestHeaders.Add("x-token", jwToken);
         // Get response
        HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
        if (response.IsSuccessStatusCode)
        {
            // pass
            string json = response.Content.ReadAsStringAsync().Result;
            // New Rec
            return System.Text.Json.JsonSerializer.Deserialize<RecoveryResponse>(json);
        }
        else
        {
            // fail
            string error = response.Content.ReadAsStringAsync().Result;
            throw new Exception(error);
        }
    }
    private static bool CheckExpired(string jwToken)
    {
        // Split JwToken into components header.payload.signature
        string[] values = jwToken.Split('.');
        byte[] payloadBytes = Base64Url.Decode(values[1]);
        var sPayLoad = Encoding.UTF8.GetString(payloadBytes);
        Dictionary<string, object> payload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(sPayLoad);

        object tokenExp;
        payload.TryGetValue("exp", out tokenExp);
        if (tokenExp == null)
        {
            throw new ApplicationException("JWK missing from header"); // should never happen
        }
        var tokenTicks = long.Parse(tokenExp.ToString());
        var tokenDate = DateTimeOffset.FromUnixTimeSeconds(tokenTicks).UtcDateTime;
        var now = DateTime.UtcNow;
        var valid = tokenDate.AddDays(-2) <= now;
        return valid;
    }

    public static void SaveStore(string userTokenPath, DeviceStore store)
    {
        // Serialise
        JsonSerializerOptions jso = new JsonSerializerOptions();
        jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        string json = JsonSerializer.Serialize<DeviceStore>(store, jso);
        System.IO.File.WriteAllText(userTokenPath, json);

    }
   
    public static byte[] GenerateProtectedDeviceKey()
        {
            // Generate 32 byte random device key, this is injected in the hardware version of a Fido token.
            byte[] _key = Shake256.HashData(RandomNumberGenerator.GetBytes(64),32);
            // Security Policy
            // In order to prevent digital copying, this protection must be bound to an unique account or process.
            // The protected key is never stored within the provider, and is never in plaintext outside of the provider.
            return ProtectedData.Protect(_key, null, DataProtectionScope.CurrentUser);
        }
        public static string DeviceIdentity(byte[] publickey)
        {
            // Build public key bytes[]
            return "0199" + RIPEMD160.Create().ComputeHash(publickey).ToHex();
        }
    public static byte[] JwkToPKeyBytes(string jwkJson)
    {
        using (JsonDocument doc = JsonDocument.Parse(jwkJson))
        {
            JsonElement root = doc.RootElement;
            string X = root.GetProperty("X").GetString();
            return Base64UrlEncoder.DecodeBytes(X);
        }

    }
      
    public static void IncrementCounter(string tokenPath)
    {
        DeviceStore ds = GetStore(tokenPath);
        ds.Counter = ds.Counter + 1;
        // Save
        SaveStore(tokenPath, ds);
    }
   
    public static string ExportEcdhToJwk(byte[] pubkey)
    {
        // Build JsonWebKey
        MemoryStream ms = new MemoryStream();
        using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("Alg");
            writer.WriteStringValue("X25519"); 
            writer.WritePropertyName("Kty");
            writer.WriteStringValue("OKP");
            writer.WritePropertyName("Kid");
            writer.WriteStringValue(BinaryAscii.hexFromBinary(RIPEMD160.Create().ComputeHash(pubkey)));
            writer.WritePropertyName("Crv");
            writer.WriteStringValue("Curve25519");
            writer.WritePropertyName("X");
            writer.WriteStringValue(Base64UrlEncoder.Encode(pubkey));
            writer.WriteEndObject();

        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }
    public static string ExportEd25519ToJwk(byte[] publickey)
    {
        // Build JsonWebKey
        MemoryStream ms = new MemoryStream();
        using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("Alg");
            writer.WriteStringValue("Ed25519");
            writer.WritePropertyName("Kty");
            writer.WriteStringValue("OKP");
            writer.WritePropertyName("Kid");
            writer.WriteStringValue(RIPEMD160.Create().ComputeHash(publickey).ToHex());
            writer.WritePropertyName("Crv");
            writer.WriteStringValue("Curve25519");
            writer.WritePropertyName("X");
            writer.WriteStringValue(Base64UrlEncoder.Encode(publickey));
            writer.WriteEndObject();

        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }
    public static string ExportX25519ToJwk(byte[] publickey)
    {
        // Build JsonWebKey
        MemoryStream ms = new MemoryStream();
        using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("Alg");
            writer.WriteStringValue("X25519");
            writer.WritePropertyName("Kty");
            writer.WriteStringValue("OKP");
            writer.WritePropertyName("Kid");
            writer.WriteStringValue(RIPEMD160.Create().ComputeHash(publickey).ToHex());
            writer.WritePropertyName("Crv");
            writer.WriteStringValue("Curve25519");
            writer.WritePropertyName("X");
            writer.WriteStringValue(Base64UrlEncoder.Encode(publickey));
            writer.WriteEndObject();

        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }
    /// <summary>
    /// Register Device
    /// </summary>
    /// <param name="sin">Secure Identity</param>
    /// <returns>KeyHandle</returns>
    /// <exception cref="Exception"></exception>
    public DeviceStore Register()
    {

        // FIDO AppId->SecureIdentity
        byte[] Appid = Encoding.UTF8.GetBytes(ds.SecureIdentity);
        // Generate registration nounce
        byte[] nounce = new byte[32];
        RandomNumberGenerator.Create().GetBytes(nounce);
        // Derive private key .
        byte[] _keyBytes = DeriveKey(Appid, nounce);
        byte[] KeyHandle = DeriveKeyHandle(nounce, Appid, _keyBytes);
        // Ed25519 signatures
        Edward25519.KeyPair kp = Edward25519.Ed25519.GenerateKeyPair(_keyBytes);

        // Return DeviceStore 
        DeviceStore d = new DeviceStore();
        d.ProtectedDeviceKey = ds.ProtectedDeviceKey;
        d.SecureIdentity = ds.SecureIdentity;
        d.KeyHandle = KeyHandle;
        d.JwKey = ExportEd25519ToJwk(kp.PublicKey);
        d.DeviceSin = DeviceIdentity(kp.PublicKey);
        return d;

    }
    
    public string GetX25519PublicKey()
    {
        // FIDO AppId->SecureIdentity
        byte[] Appid = Encoding.UTF8.GetBytes(ds.SecureIdentity);
        // Generate registration nounce
        byte[] nounce = new byte[32];
        RandomNumberGenerator.Create().GetBytes(nounce);
        // Derive private key .
        byte[] _keyBytes = DeriveKey(Appid, nounce);
        byte[] KeyHandle = DeriveKeyHandle(nounce, Appid, _keyBytes);
        // Ed25519 signatures
        Edward25519.KeyPair kp = Edward25519.Curve25519.GenerateKeyPair(_keyBytes);
        return ExportX25519ToJwk(kp.PublicKey);

    }

    /// <summary>
    /// Sign and return Signature (bytes[]),
    /// </summary>
    /// <param name="keyHandle"></param>
    /// <param name="hashData"></param>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    public string  SignHash(byte[] hashData)
    {
        // Ed25519
        byte[] signature = Edward25519.Ed25519.Sign(hashData, _kp);
        return Base64Url.Encode(signature);
    }

    private byte[] DeriveKey(byte[] keyHandle)
    {
        byte[] sinBytes = Encoding.UTF8.GetBytes(ds.SecureIdentity);
        MemoryStream ms = new MemoryStream(keyHandle);
        BinaryReader binaryReader = new BinaryReader(ms);
        // Extract nonce from key handle
        Byte[] nounce = binaryReader.ReadBytes(32);
        // Derive key
        byte[] _key = DeriveKey(sinBytes, nounce);
        // Verify KeyHandle
        byte[] _keyhandle = DeriveKeyHandle(nounce, sinBytes, _key);
        if (ByteArrayCompare(_keyhandle, keyHandle) == false)
        {
            throw new Exception("KeyHandle Error.");
        }
        return _key;
    }

    public string XShare(string jwkJson)
    {
        byte[] pKeyBytes = JwkToPKeyBytes(jwkJson);
        var keys = Edward25519.KeyAgreement.GenerateKeyPair(); // ephemerial
        return ExportEcdhToJwk(keys.PublicKey);
    }
    #region schannel
    /// <summary>
    /// Encrypt session
    /// </summary>
    /// <param name="data"></param>
    /// <param name="jwtoken">xxxxMe Token</param>
    /// <returns></returns>
    public Dictionary<byte[], byte[]> Encrypt(byte[] data, string jwtoken)
    {
        Guid jti = FidoProvider.ExtractJti(jwtoken);
        string jwk = FidoProvider.ExtractJwk(jwtoken);
        byte[] pk = FidoProvider.JwkToPKeyBytes(jwk);
        // Derive session key
        var dict = new Dictionary<byte[], byte[]>();
        Dictionary<string, byte[]> d = DeriveSessionKey(jti, jwk);
        byte[] _key = d.FirstOrDefault().Value;
        byte[] cipherText = OneCipher.XEncrypt(_key, data);
        dict.Add(cipherText, _key);
        CryptographicOperations.ZeroMemory(_key);
        return dict;
    }
    public Dictionary<string, byte[]> ShareEncrypt(byte[] data, string jwtoken)
    {
        Guid jti = FidoProvider.ExtractJti(jwtoken);
        string jwk = FidoProvider.ExtractJwk(jwtoken);
        byte[] pk = FidoProvider.JwkToPKeyBytes(jwk);
        // Derive session key
        Dictionary<string, byte[]> d = SharedSecret(jwtoken);
        string _jwk = d.FirstOrDefault().Key;
        byte[] _key = d.FirstOrDefault().Value;
        byte[] cipherText = OneCipher.XEncrypt(_key, data);
        Dictionary<string, byte[]> dict = new Dictionary<string, byte[]>();
        dict.Add(_jwk, cipherText);
        CryptographicOperations.ZeroMemory(_key);
        return dict;
    }
    /// <summary>
    /// Decrpt session 
    /// </summary>
    /// <param name="cipherText">host encrypted content</param>
    /// <param name="jti"></param>
    /// <param name="jwk"></param>
    /// <returns></returns>
    public byte[] Decrypt(byte[] cipherText, Guid jti, string jwk)
    {
        Dictionary < string, byte[]> dict = DeriveSessionKey(jti, jwk);
        byte[] _key = dict.FirstOrDefault().Value;
        byte[] obj = OneCipher.XDecrypt(_key, cipherText);
        CryptographicOperations.ZeroMemory(_key);
        return obj;
    }
    #endregion 
    public Dictionary<string, byte[]> SharedSecret(string jwtoken)
    {
        string jwk = FidoProvider.ExtractJwk(jwtoken);
        byte[] pKeyBytes = JwkToPKeyBytes(jwk);
        var keys = Edward25519.KeyAgreement.GenerateKeyPair(); // ephemerial
        byte[] sharedSecret = Edward25519.KeyAgreement.Agreement(keys.PrivateKey, pKeyBytes);
        var dict = new Dictionary<string, byte[]>();
        string sjwk = ExportEcdhToJwk(keys.PublicKey);
        dict.Add(sjwk, sharedSecret);
        return dict;
    }
    /// <summary>
    /// Deterministic device One Cipher ephemerial key
    /// </summary>
    /// <param name="jti"></param>
    /// <param name="jwk"></param>
    /// <returns></returns>
    private Dictionary<string, byte[]> DeriveSessionKey(Guid jti, string jwk)
    {

        byte[] _key = DeriveKey(ds.KeyHandle);
        var dKey = Shake256.HashData(_key.Concat(jti.ToByteArray()).ToArray(), 32); // add jti (GRND entropy) to static _key
        var kp = Edward25519.Ed25519.GenerateKeyPair(dKey);
        byte[] sharedSecret = Edward25519.KeyAgreement.Agreement(kp.PrivateKey, JwkToPKeyBytes(jwk));
        var dict = new Dictionary<string, byte[]>();
        string sjwk = ExportEcdhToJwk(kp.PublicKey);
        dict.Add(sjwk, sharedSecret);
        return dict;
    }

    private byte[] GetDeviceKey()
    {
        return ProtectedData.Unprotect(ds.ProtectedDeviceKey, null, DataProtectionScope.CurrentUser);
    }

    private bool ByteArrayCompare(byte[] a1, byte[] a2)
    {
        if (a1.Length != a2.Length)
            return false;

        for (int i = 0; i < a1.Length; i++)
            if (a1[i] != a2[i])
                return false;
        return true;
    }
    private byte[] IntToBytes(int value)
    {
        byte[] intBytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(intBytes);
        byte lastByte = intBytes.Select(x => (byte)x).ToArray().Last();
        return new byte[] { lastByte };
    }
    private byte[] DeriveKeyHandle(byte[] nounce, byte[] appId, byte[] privateKeyBytes)
    {
        //KeyHandle=nonce,HMAC(AppID,PrivateKey)
        MemoryStream keyHandleBuff = new MemoryStream();
        BinaryWriter keyHandleWriter = new BinaryWriter(keyHandleBuff);
        // Write keyHandle ->nounce
        keyHandleWriter.Write(nounce);
        // Compute HMAC(AppID,PrivateKey)
        MemoryStream macBuff = new MemoryStream();
        BinaryWriter macWriter = new BinaryWriter(macBuff);
        macWriter.Write(nounce);          // Attest binding to nonce, not in fido spec (add Aug 2023)
        macWriter.Write(appId);        // AppID->HSM secure identity
        macWriter.Write(privateKeyBytes); // EcDsa IEEE PrivateKey
                                          // Write keyHandle -> HMAC(AppID,PrivateKey)
        byte[] _deviceKey = GetDeviceKey();
        var hmac256 = new HMACSHA256(_deviceKey); // preloaded device key
                                                  // Compute Signature or keyHandle attestation data
        var sign = hmac256.ComputeHash(macBuff.ToArray());
        keyHandleWriter.Write(sign);
        //KeyHandle=nonce,HMAC(AppID,PrivateKey)
        byte[] KeyHandle = keyHandleBuff.ToArray();
        return KeyHandle;
    }
    public bool VerifyKeyHandle(byte[] keyHandle)
    {
        MemoryStream ms = new MemoryStream(keyHandle);
        BinaryReader binaryReader = new BinaryReader(ms);
        // Extract nonce from key handle
        Byte[] nounce = binaryReader.ReadBytes(32);
        byte[] sinBytes = Encoding.UTF8.GetBytes(ds.SecureIdentity);
        byte[] _PrivateCngKeyBytes = DeriveKey(sinBytes, nounce);

        // Verify KeyHandle bytes which includes signature
        byte[] _keyhandle = DeriveKeyHandle(nounce, sinBytes, _PrivateCngKeyBytes);
        return ByteArrayCompare(_keyhandle, keyHandle);

    }
    private byte[] DeriveKey(byte[] appId, byte[] keyHandle)
    {
        // Extarct
        byte[] nounce = keyHandle.Take(32).ToArray();
        byte[] _deviceKey = GetDeviceKey();
        using (var hmac256 = new HMACSHA256(_deviceKey)) // seed SHA256 with device key
        {
            // PrivateKey=HMAC(AppID+nonce,DeviceKey) 
            MemoryStream pKeyBuff = new MemoryStream();
            BinaryWriter pKeyWriter = new BinaryWriter(pKeyBuff);
            pKeyWriter.Write(appId);
            pKeyWriter.Write(nounce);
            byte[] privateKeyBytes = hmac256.ComputeHash(pKeyBuff.ToArray());
            // privateKeyBytes is essentially a deterministic, random 32 byte array 

            return privateKeyBytes;

        }
    }


}
