  public class Support
  {
      public static Guid MaxValue = new Guid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
     
      public static string MsgMe(string userTokenPath)
      {
          FidoProvider fp = FidoProvider.GetProvider(userTokenPath);
          // Extract endpoint from Device Token
          Uri _baseUri = new Uri(fp.Audience());

          // Obtain Function JwToken
          HttpClient _httpClient = new HttpClient();
          // Build funtion endpoint Uri
          string _relativeUrl = "User/MsgMe";
          Uri _uri = new Uri(_baseUri, _relativeUrl);
          _httpClient.BaseAddress = _baseUri;
          // Add Device Jwtoken
          _httpClient.DefaultRequestHeaders.Add("x-token", fp.GetJwToken());
          // Add device signature
          byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(fp.GetJwToken()));
          string signature = fp.SignHash(hashBytes);
          _httpClient.DefaultRequestHeaders.Add("x-jws-signature", signature);
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
      public static string SignMe(string userTokenPath)
      {
          FidoProvider fp = FidoProvider.GetProvider(userTokenPath);
          // Extract endpoint from Device Token
          Uri _baseUri = new Uri(fp.Audience());

          // Obtain Function JwToken
          HttpClient _httpClient = new HttpClient();
          // Build funtion endpoint Uri
          string _relativeUrl = "User/SignMe";
          Uri _uri = new Uri(_baseUri, _relativeUrl);
          _httpClient.BaseAddress = _baseUri;
          // Add Device Jwtoken
          _httpClient.DefaultRequestHeaders.Add("x-token", fp.GetJwToken());
          // Add device signature
          byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(fp.GetJwToken()));
          string signature = fp.SignHash(hashBytes);
          _httpClient.DefaultRequestHeaders.Add("x-jws-signature", signature);
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
      #region Vault
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
          _httpClient.DefaultRequestHeaders.Add("x-token", fp.GetJwToken());
          // Add device signature
          byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(fp.GetJwToken()));
          string ssign = fp.SignHash(hashBytes);
          _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
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

          if (objectbytes.Length > fp.ExtractSize(vaultMeToken))
          {
              throw new Exception("Exceeded Size limit of " + fp.ExtractSize(vaultMeToken) + " MB.");
          }

          // Extract endpoint from Device Token
          Uri _baseUri = new Uri(fp.Audience());
          // Obtain Function JwToken
          HttpClient _httpClient = new HttpClient();
          // Build funtion endpoint Uri
          string _relativeUrl = "Object/Add";
          Uri _uri = new Uri(_baseUri, _relativeUrl);
          _httpClient.BaseAddress = _baseUri;
          // Add VaultMe Jwtoken
          _httpClient.DefaultRequestHeaders.Add("x-token", vaultMeToken);

          // Encrypt Object 
          Dictionary<byte[], byte[]> d = fp.Encrypt(objectbytes, vaultMeToken);
          byte[] pContentBytes = d.FirstOrDefault().Key;
          byte[] sKey = d.FirstOrDefault().Value;

          // Generate ephemeral share
          Dictionary<string, byte[]> dict = fp.SharedSecret(vaultMeToken);
          string _sjwk = dict.FirstOrDefault().Key;
          byte[] _key = dict.FirstOrDefault().Value;

          // Wrapp Session key with shared  secret
          byte[] _pkey = OneCipher.XEncrypt(_key, sKey);

          // Add protectedVaulted object content to Post 
          ByteArrayContent content = new ByteArrayContent(pContentBytes);

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
      private static ObjectToken Decode(string json)
      {
          string content = json.Split('.')[1]; // second segment
          var jsonpayload = FidoProvider.Base64Url.Decode(content);
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
                      sig.ObjectHash = FidoProvider.Base64Url.Decode(value.ToString());
                      break;

              }

          }
          sig.Verified = JwtProvider.ValidateJwToken(json);
          return sig;

      }

      public static ObjectToken Verify(string json)
      {
          ObjectToken sign = Decode(json);
          sign.Verified = JwtProvider.ValidateJwToken(json); // Validate Signature JWToken contents.
          return sign;
      }
      public static Dictionary<string, byte[]> Protect(FidoProvider fp, byte[] data, string filename,  string vaultMeToken)
      {
          // Encrypt Object 
          Dictionary<byte[], byte[]> d = fp.Encrypt(data, vaultMeToken);
          byte[] pContentBytes = d.FirstOrDefault().Key;
          byte[] sKey = d.FirstOrDefault().Value;

          // Generate ephemeral share
          Dictionary<string, byte[]> dict = fp.SharedSecret(vaultMeToken);
          string _sjwk = dict.FirstOrDefault().Key; 
          byte[] _key = dict.FirstOrDefault().Value;

          // Wrapp Session key with shared  secret
          byte[] _pkey = OneCipher.XEncrypt(_key, sKey);

          // Create Object Information
          Guid objId = Guid.NewGuid();
          dict = new Dictionary<string, byte[]>();
          string objInfo = Encode(fp, data, filename, _sjwk, _pkey, objId);
          dict.Add(objInfo, pContentBytes);
          return dict;
      }
      private static string Encode(FidoProvider fp, byte[] objectBytes, string filename, string jwk, byte[] pkey, Guid? objectId, DateTime? filedate = null)
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
          string encodedJwEHeader = FidoProvider.Base64Url.Encode(ms.ToArray());
          string encodedHash = Convert.ToBase64String(hashBytes);

          // serialise Payload
          ms = new MemoryStream();
          using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
          {
              writer.WriteStartObject();
              writer.WritePropertyName("Type");
              writer.WriteStringValue("ObjectInfo"); // Object Meta data, peper One Cipher encrypted object is inside Post
              writer.WritePropertyName("SecureIdentity");
              writer.WriteStringValue(fp.GetSecureIdentity());
              writer.WritePropertyName("DeviceIdentity");
              writer.WriteStringValue(fp.GetDeviceSin());
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
              writer.WriteNumberValue(fp.GetCounter());
              writer.WriteEndObject();

          }
          string encodedPayload = FidoProvider.Base64Url.Encode(ms.ToArray());
          byte[] sigBytes = Encoding.UTF8.GetBytes(encodedJwEHeader + "." + encodedPayload);
          string sig = fp.SignHash(sigBytes);
          string encodedJWESignature = sig;
          return encodedJwEHeader + "." + encodedPayload + "." + encodedJWESignature;
      }

      public class VaultedResponse
      {
          public Guid Jti { get; set; }
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
          
          public static VaultedResponse Decode(string json)
          {
              var _payload = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
              // Decode Vaulted Object
              VaultedResponse vo = new VaultedResponse();
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
                      case "jti":
                          vo.Jti = new Guid(value.ToString());
                          break;
                      case "uri":
                          vo.Download = new Uri(value.ToString());
                          break;
                  }

              }
              return vo;
          }
      }
      #endregion

      public class Signature
      {
          // The r and s are unsigned, big endian numbers, but little indian within this implementation.

          public byte[] rBa { get; private set; }
          public byte[] sBa { get; private set; }

          /// <summary>
          /// ASN.1 Signature SEQUENCE INTEGER R, INTEGERS
          /// as little endian format.
          /// </summary>
          /// <param name="rsBytes"></param>       
          public Signature(byte[] r, byte[] s)
          {
              this.rBa = r;
              this.sBa = s;
          }
          public Signature(byte[] rsBytes)
          {
              FromDER(rsBytes);
          }
         

          /// <summary>
          /// r and s are unsigned, little endian numbers.
          /// </summary>
          /// <returns></returns>
          public byte[] SignatureBytes()
          {
              // Handles full range of BigIntegers (64->66  bytes) within a EC Signatures
              return ToDER();
          }

          /*
           * Signature ::= SEQUENCE 
           * {
                  r   INTEGER,
                  s   INTEGER
             }
             When encoded in DER, this becomes the following sequence of bytes: 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
              where:
              b1 is a single byte value, equal to the length, in bytes, of the remaining list of bytes (from the first 0x02 to the end of the encoding);
              b2 is a single byte value, equal to the length, in bytes, of (vr);
              b3 is a single byte value, equal to the length, in bytes, of (vs);
              (vr) is the signed big-endian encoding of the value "r
              ", of minimal length;
              (vs) is the signed big-endian encoding of the value "s
              ", of minimal length.

              "Signed big-endian encoding of minimal length" means that the numerical value must be encoded as a sequence of bytes, 
              such that the least significant byte comes last (that's what "big endian" means), the total length is the shortest possible to represent the value (that's "minimal length"), and the first bit of the first byte specifies the sign of the value (that's "signed"). 
              For ECDSA, the r  and s  values are positive integers, so the first bit of the first byte must be a 0; i.e. the first byte of (vr) (respectively (vs)) must have a value between 0x00 and 0x7F.

              For instance, if we were to encode the numerical value 117, it would use a single byte 0x75, and not a two-byte sequence 0x00 0x75 (because of minimality). However, the value 193 must be encoded as two bytes 0x00 0xC1, 
              because a single byte 0xC1, by itself, would denote a negative integer, since the first (aka "leftmost") bit of 0xC1 is a 1 (a single byte of value 0xC1 represents the value -63).

              The Javascript code invokes a method called toByteArrayUnsigned; that name is evocative of conversion to an unsigned representation (i.e. always positive, even if the first bit is a 1), and that's wrong for DER
           */
          public byte[] ToDER()
          {
              // ASN.1 encoding
              /*
               * LENGTH
               * The short form is a single byte, between 0 and 127. 
               * The long form is at least two bytes long, and has bit 8 of the first byte set to 1. 
               * Bits 7-1 of the first byte indicate how many more bytes are in the length field itself.
               * As all LENGH are less than 127 a single byte is used
               */
              List<byte> bytes = new List<byte>();
              bytes.Add((byte)0x30);// SEQUENCE
                                    // 6 = 1 byte for each SEQUENCE, LENGHT; INTEGER,LENGHT;INTEGER,LENGHT
              int l = 6 + rBa.Length + sBa.Length;
              bytes.Add((byte)l); //LENGHT
                                  //R
              bytes.Add((byte)0x02); //INTEGER
              bytes.Add((byte)rBa.Length);
              bytes.AddRange(rBa);

              //S
              bytes.Add((byte)0x02); //INTEGER
              bytes.Add((byte)sBa.Length);
              bytes.AddRange(sBa);
              return bytes.ToArray();
          }
          public void FromDER(byte[] derBytes)
          {

              MemoryStream ms = new MemoryStream(derBytes);
              BinaryReader binaryReader = new BinaryReader(ms);
              binaryReader.ReadByte(); // SEQUENCE
              int derLength = (int)binaryReader.ReadByte(); //Length

              //R
              binaryReader.ReadByte(); // INTEGER 
              int rlength = (int)binaryReader.ReadByte(); //Length
              rBa = binaryReader.ReadBytes(rlength);

              //S
              binaryReader.ReadByte(); // INTEGER 
              int slength = (int)binaryReader.ReadByte(); //Length
              sBa = binaryReader.ReadBytes(slength);


          }
      }

  }
  public class MsgToken
  {
      public Guid Jti { get; set; }
      public Guid MsgId { get; set; }
      public string SecureIdentity { get; set; }
      public string Recsin { get; set; }
      public string Recjwt { get; set; } // ConnectMe Token 
      public byte[] Cnt { get; set; }
      public string Mimetype { get; set; }
      public string FileName { get; set; }
      public string Subject { get; set; }
      public string Jwk { get; set; }
      public string JwToken { get; set; } // MsgMe Token
      public DateTime Expire { get; set; }
      public bool Verified { get; set; }

      public MsgToken()
      {
          Verified = false;
      }

      public static MsgToken VerifyToken(string json)
      {
          MsgToken sign = DecodeMsg(json);
          sign.Verified = JwtProvider.ValidateJwToken(json); // Validate Signature JWToken contents.
          return sign;
      }
      public static string Encode(FidoProvider fp, byte[] msgbytes, string filename, string msgMeToken,  Guid jti, Guid? msgId, DateTime? expire = null)
      {
          // Session Encrypt Msg 
          Dictionary<string, byte[]> dict = fp.ShareEncrypt(msgbytes, msgMeToken);
          byte[] pMsgBytes = dict.FirstOrDefault().Value;
          string sjwk = dict.FirstOrDefault().Key;

          byte[] hashBytes = Shake256.HashData(msgbytes, 64); // Quantum safe for long term verification of object storage 
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
          string encodedJwEHeader = FidoProvider.Base64Url.Encode(ms.ToArray());
          string encodedHash = Convert.ToBase64String(hashBytes);

          // serialise Payload
          ms = new MemoryStream();
          using (Utf8JsonWriter writer = new Utf8JsonWriter(ms))
          {
              writer.WriteStartObject();
              writer.WritePropertyName("Type");
              writer.WriteStringValue("ObjectInfo"); // Object Meta data, peper One Cipher encrypted object is inside Post
              writer.WritePropertyName("Jti");
              writer.WriteStringValue(jti.ToString());
              writer.WritePropertyName("SecureIdentity");
              writer.WriteStringValue(fp.GetSecureIdentity());
              writer.WritePropertyName("Cnt");
              writer.WriteStringValue(Convert.ToBase64String(pMsgBytes));
              writer.WritePropertyName("Filename");
              writer.WriteStringValue(filename);
              writer.WritePropertyName("JwToken");
              writer.WriteStringValue(msgMeToken);
              writer.WritePropertyName("Jwk");
              writer.WriteStringValue(sjwk);
              if (expire.HasValue)
              {
                  DateTime src = expire.Value;
                  writer.WritePropertyName("Expire");
                  writer.WriteStringValue(new DateTime(src.Year, src.Month, src.Day, src.Hour, 0, 0)); // remove min and sec
              }
              if (msgId.HasValue)
              {
                  writer.WritePropertyName("MsgId");
                  writer.WriteStringValue(msgId.Value);
              }
              writer.WriteEndObject();

          }
          string encodedPayload = FidoProvider.Base64Url.Encode(ms.ToArray());
          byte[] sigBytes = Encoding.UTF8.GetBytes(encodedJwEHeader + "." + encodedPayload);
         string sig = fp.SignHash(sigBytes);
          string encodedJWESignature = sig;
          return encodedJwEHeader + "." + encodedPayload + "." + encodedJWESignature;
      }

     
      private static MsgToken DecodeMsg(string json)
      {
          string content = json.Split('.')[1]; // second segment
          var jsonpayload = FidoProvider.Base64Url.Decode(content);
          var _payload = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonpayload);
          // Decode msg
          MsgToken msg = new MsgToken();
          foreach (KeyValuePair<string, object> kvp in _payload)
          {
              string key = kvp.Key.ToLower();
              object value = kvp.Value;
              switch (key.ToLower())
              {
                  case "secureidentity":
                      msg.SecureIdentity = value.ToString();
                      break;
                  case "cnt":
                      msg.Cnt = Convert.FromBase64String(value.ToString());
                      break;
                  case "jwk":
                      msg.Jwk = value.ToString();
                      break;
                  case "filename":
                      msg.FileName = value.ToString();
                      break;
                  case "subject":
                      msg.Subject = value.ToString();
                      break;
                  case "msgid":
                      msg.MsgId = new Guid(value.ToString());
                      break;
                  case "jti":
                      msg.Jti = new Guid(value.ToString());
                      break;
                  case "expire":
                      DateTime fDateTime;
                      DateTime.TryParse(value.ToString(), out fDateTime);
                      msg.Expire = fDateTime;
                      break;
                
              }

          }
          msg.Verified = JwtProvider.ValidateJwToken(json);
          return msg;

      }

   

  }
