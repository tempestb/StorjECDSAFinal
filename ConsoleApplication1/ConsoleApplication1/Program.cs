using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;


// These methods use BouncyCastle.  You will need to get that and install it first.

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
        }

        // This will get you the keys... 
        public static AsymmetricCipherKeyPair GenerateKeys(int keySize)
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var ps = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256k1");
            var ecParams = new ECDomainParameters(ps.Curve, ps.G, ps.N, ps.H);
            var keyGenParam = new ECKeyGenerationParameters(ecParams, secureRandom);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();
        }

        // I call it like this:  var key = GenerateKeys(256); 

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






    }
}
