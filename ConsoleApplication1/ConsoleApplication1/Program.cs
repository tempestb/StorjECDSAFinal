using System;
using System.Net;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System.IO;


// These methods use BouncyCastle.  You will need to get that and install it first.

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
        }

        // This will get you the keys... 
        public static AsymmetricCipherKeyPair GenerateKeys()
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var ecParams = new ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H);
            var keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();
        }

        // To get a signature...
        public static byte[] GetSignature(string plainText, AsymmetricCipherKeyPair key)
        {
            var encoder = new ASCIIEncoding();
            var inputData = encoder.GetBytes(plainText);

            var signer = SignerUtilities.GetSigner("ECDSA");
            signer.Init(true, key.Private);
            signer.BlockUpdate(inputData, 0, inputData.Length);

            return signer.GenerateSignature();
        }

        // You can use the above example if you don't want to split the keys.  The below example deals with the keys being split.  I split them like so...
        // var publicKey = (ECPublicKeyParameters)(key.Public);
        // var privateKey = (ECPrivateKeyParameters)(key.Private);

        // Then you can simply sign the data with the Private Key below...

        public static string SignData(string msg, AsymmetricKeyParameter privKey)
        {
            try
            {
                byte[] msgBytes = Encoding.UTF8.GetBytes(msg);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                signer.Init(true, privKey);
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                byte[] sigBytes = signer.GenerateSignature();

                return ToHex(sigBytes);
            }
            catch (Exception exc)
            {
                Console.WriteLine("Signing Failed: " + exc.ToString());
                return null;
            }
        }

        // Simple ToHex function used above.
        public static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "");
        }


        // 01/02/2017
        // As requested, below is an example of how I talk to Storj.  Note, that I've provided an example of a POST and  GET operation, as the
        // format is different.

        public string strGETTOKEN(string strBUCKETID, string strOperation)
        {

            // strBUCKETID is the Storj BUCKETID.
            // strOperation is PUSH or PULL.  Meaning you intend to either push data to the bucket, or pull data from the bucket.

            string strAPIURL = "http://api.storj.io/";  // I normally get it from the web.config via this command...
                                                        // ConfigurationManager.AppSettings["strAPIURL"].ToString();

            string strPUBKEY = "User's Public Key";  // strPUBKEY = ToHex(publicKey2.Q.GetEncoded()).ToLower();
            string strUSER = "User name";  // Not email unless that is also the user's name.

            string strUUID = strUURAND();  // Nonce.  Essentially Guid.NewGuid().ToString()

            // This is the concatenated query string.  Note, that it might make sense to build this into an object first and then serialize it
            // and deserialize it when needed.  It makes it easier to apply changes.  But this was trial and error for me, so I went this route.
            string requestData = "POST\n/buckets/" + strBUCKETID + "/tokens\n{\"operation\":\"" + strOperation + "\",\"__nonce\":\"" + strUUID + "\"}";
            // Here is where we sign the query string.
            string strSIGNEDDATA = SignString(requestData, strUSER).ToLower();  // This method first reconstructs the keypair (Because I split
                                                                                // the keys.  If you aren't splitting the keys, you can just
                                                                                // call SignData instead, and pass it your BouncyCastle keypair.
                                                                                //  If you do happen to split the keys, I can provide this method,
                                                                                //  but because it touches Entity Framework, I didn't want to 
                                                                                //  overly complicate this example.

            // The API call.
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(strAPIURL + "buckets/" + strBUCKETID + "/tokens");

            // Operation on the API
            request.Method = "POST";
            // This can probably be smaller.  I set these timeouts when the Bridge was having difficulties.
            request.Timeout = 30000;
            request.ContentType = "application/json";
            // These are the header variables.  Essentially the signed string above, and the public key.
            request.Headers.Add("x-signature", strSIGNEDDATA);
            request.Headers.Add("x-pubkey", strPUBKEY);

            // We're going fishing, so we find an empty stream.
            Stream dataStream = null;

            // So with a POST, we need to create the parameters in a separate string from the query string.  
            // Normally, I just use this string, and attach it to the query string above by way of a variable, but I wanted it to be clear
            // here with what is happening.
            string requestData2 = "{\"operation\":\"" + strOperation + "\",\"__nonce\":\"" + strUUID + "\"}";

            // Byte conversion
            byte[] data = Encoding.UTF8.GetBytes(requestData2);

            try
            {
                // Connect our stream.
                dataStream = request.GetRequestStream();
                // Write the data to the stream.
                dataStream.Write(data, 0, data.Length);
                // Dispose of the stream.  (This will close and dispose)
                dataStream.Dispose();

                // Now we'll see if we've caught anything.
                WebResponse response = request.GetResponse();
                string result = new StreamReader(response.GetResponseStream()).ReadToEnd();
                // Keeping things tidy, we'll dispose of the response object here as well.  Granted, this would be better with Using statements.
                response.Dispose();
                string strJsonTokenString = "";
                // We get the results in JSON.  So we'll deserialize it, take the token out, and pass that as our return.
                var jsonStorjToken = JsonConvert.DeserializeObject<StorjToken>(result);
                strJsonTokenString = jsonStorjToken.token;
                return strJsonTokenString;
            }
            catch (Exception ex)
            {
                // Error Log Routine removed for clarity.
                return null;
            }

        }


        public string strGETFRAME()
        {

            string strAPIURL = "http://api.storj.io/";  // I normally get it from the web.config via this command...
                                                        // ConfigurationManager.AppSettings["strAPIURL"].ToString();
            string strPUBKEY = "User's Public Key";  // strPUBKEY = ToHex(publicKey2.Q.GetEncoded()).ToLower();
            string strUSER = "User name";  // Not email unless that is also the user's name.

            string strUUID = strUURAND();  // Nonce.  Essentially Guid.NewGuid().ToString()

            // So here we have the GET operation with only the nonce parameter.  
            string requestData = "GET\n/frames\n__nonce=" + strUUID;
            // Again, could just put requestData2 above requestData and then concatenate it in requestData.  Left it this way for clarity.
            string requestData2 = "__nonce=" + strUUID;
            // We sign it.  If you aren't splitting keys, you can call SignData instead, and pass your keypair instead of the user.
            string strSIGNEDDATA = SignString(requestData, strUSER).ToLower();

            // We connect to the API
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(strAPIURL + "frames?" + requestData2);

            // Our new operation
            request.Method = "GET";
            request.Timeout = 30000;
            request.ContentType = "application/json";
            // Our header variables
            request.Headers.Add("x-signature", strSIGNEDDATA);
            request.Headers.Add("x-pubkey", strPUBKEY);

            // We're going fishing, so let's first find an empty stream.
            Stream dataStream = null;

            try
            {
                // Connect the stream.
                dataStream = request.GetResponse().GetResponseStream();
            }
            catch (Exception ex)
            {
                // Error logging routine;
                return null;
            }

            // We got something, let's reel it in.
            StreamReader responseReader = new StreamReader(dataStream);
            string response2 = responseReader.ReadToEnd();
            // And we wash our hands.
            responseReader.Dispose();

            // We'll convert the output.  // If you want the StorjFrame object, let me know and I'll include it in a revision.
            var StorjFrame = JsonConvert.DeserializeObject<List<StorjFrame>>(response2);

            string strStorjFrameReturn = "";

            // Since StorjFrame is a list object.  We are looking to see if it contains anything at all.  Currently, I am only interested in the
            // first entry.  The protocol has recently changed, and I believe it will send back multiple frames for multiple shards if requested
            // but I have not modified my code to manage that as of yet.
            if (StorjFrame.Any())
            {
                var items = from item in StorjFrame
                            select item;
                foreach (var item in items)
                {
                    // Again, we know there will only be one result we're interested in here.  But this could be modified to handle multiple.
                    strStorjFrameReturn = item.id;
                }
            }
            else
            {
                return null;
            }

            return strStorjFrameReturn;

        }

    }
}
