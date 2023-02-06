using System.Security.Cryptography;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine("Hello, world!");
        Yii2Aes256CbcEncrypter.TestData();
        // The sample encryption key. Must be 32 characters.
        string Key = "12345";

        // The sample text to encrypt and decrypt.
        string Text = "Hello, World!";

        // Encrypt and decrypt the sample text via the Aes256CbcEncrypter class.
        string Encrypted = Yii2Aes256CbcEncrypter.Encrypt(Text, Key);

        // This is a much larger string to test if the padding issue is now fixed when decrypting our text in C# bitches!
        //string Encrypted = "7/MCy24+a5sA1NypbgNiqIa4YeqIbmVBEnqAJ22KBXUzYTdiMmNmODMzN2I4ZDE4MjUwNjM0NTMxNjMzOGQxY2ExNWViNjIxYThiODQ5NjkzYTRkYmNiNDcwNGQ5YTU3z5yAYV9EOCu5zevPQq5rELUNW9Saip00UC7UP7h0c42i18k9r1J54w0QK3X/p/3eC1/QLggxkymS5cFqIKwRtkf9sYAPjXlFExR2Rj6bxrN9XRuTiueYraAQ7RvhNYnTG/rWl3dN4wLF5ims2K3DGAroI7expGE4q3FMWfESsVU=";
        // This is a test string for encryption
        //string Encrypted = "dfVDKCT1PEB08C9ffpuAx5EJfXau3caWapPsLLHdNLRhNjE4NGRhMTdjNWIzM2I3MzI3NzE1NjcyOTg4NTc4ZmYzYWRkMGQwYjYzNzdjZTE4ZjAwM2RhODIyODIwOGE5sJ/pJK96uzP4L7L1mHRSTG9UfR816QW/iYhskUN0CS6gQL313z6mkOVwuFG7rBZbzG6AmI6l6PulqtBw4rtUvQ==";
        // short
        //string Encrypted = "U3R1S2vjkJ3hJRiHIzD66KA/LKP3MrT1RQgkF9bpKWk0ODJhNjZhYzYyODgzYzA3YTMzYThhNTE5YzFmYzgwNTQxNGZkZjE1YWFjYTJkYWU0ZWU1MmQ0YWY0YjU1MmY3s4ykSmXaE1ok/3THGj2clxvNTRKnf6JmFKst3kXWsZM=";
        // Hello, World!
        //string Encrypted = "yFEK1pZlZLdpkVP6yuXOkEeWOG5R7Ovlui8JtH4Rbz9mZWIzMjM1Y2YyYmM2ZTRmNzNjYmVmYzgzNWZkN2M3YjU4ZWQ0OTc4NDJmN2Q2MWE0MTU1OTJkZTk3YTdiNTk0uKULZIu0+pU88Vx3Vc8zX8SD75xG7bn5/ltNGtdto2A=";
        //string Encrypted = "ulBD2z9Rzin1Ds4uIXK6QGpuDvB2lJRfAhBOk4+5Kdg2MGVlMDEyYTZkNTMzNjEyYmEwZGU2ZGM3ZmQxMjVlYTAxMDc3Y2EzNzU1NzI2YjUwYWRkOTRkYmFhMDQ3N2Y0ogPA4NRhphjBsh2aLBr4faQ4Zcre6iJUoeVvgfP/ulChifwQ0SjHM6GFnWxmUos2";


        // The sample encryption key. Must be 32 characters.
        //string Key = "1234567890";
        //string Encrypted = "bkqH002PrtgJWRgTcF5nyWXU8m/DdmKBjUEVMgzssB5mMmQ3OWJmZTdiYjQ3ZWVkZDdmZjkxNjQ3MzIwOTRjYjZmZmZmZmMyNGRiZmQ1MGE2YTVjODMzNDM1NGFlZjExemRRtYAqiwCekWLFR2i43t2MnngZTbU+xOCMlJCFBlvG9EG9saIKThqjrLnc4j2E";



        string Decrypted = Yii2Aes256CbcEncrypter.Decrypt(Convert.FromBase64String(Encrypted), Key);

        // Show the encrypted and decrypted data and the key used.
        Console.WriteLine("Original: {0}", Text);
        Console.WriteLine("Key: {0}", Key);
        Console.WriteLine("Encrypted: {0}", Encrypted);
        Console.WriteLine("Decrypted: {0}", Decrypted);
    }

    /**
     * A class to encrypt and decrypt strings using
     * the cipher AES-256-CBC used in Yii2.
     */
    class Yii2Aes256CbcEncrypter
    {
        private static readonly int KeySize = 256;
        private static readonly int BlockSize = 128;
        // 64 should be the correct length of the MAC if using SHA256
        private static readonly int MacHashSize = 64;

        public static string Encrypt(string plainText, string key)
        {
            byte[] allBytes = ToByteArray(plainText);
            byte[] keyByteArray = ToByteArray(key);
            string encryptedText = null;

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Generate a key salt
                var keySalt = GenerateRandomBytes(KeySize / 8);

                // hash key with keysalt and original key
                byte[] prKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, keyByteArray, (KeySize / 8), keySalt);

                // Generate an initial vector
                var iv = GenerateRandomBytes(BlockSize / 8);

                // Create a encryptor to perform the stream transform.
                var encryptor = aes.CreateEncryptor(prKey, iv);

                // Create byte array for storing our encrypted data
                byte[] encryptedBytes = new Byte[allBytes.Length];

                // Create the streams used for decryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(allBytes, 0, allBytes.Length);
                        csEncrypt.Close();
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }

                // Generate MAC for validation purposes.
                // Yii2 encryption data.
                //$authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
                //hashed = $this->hashData($iv. $encrypted, $authKey);
                //hashed = [macHash][data]
                //var mac = GenerateRandomBytes(MacHashSize);
                byte[] authKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, prKey, 32, null, ToByteArray("AuthorizationKey"));
                var mac = ToByteArray(HashData(iv, encryptedBytes, authKey));

                // Output: [keySalt][MAC][IV][ciphertext]
                // - keySalt is KeySize bytes long
                // - MAC: message authentication code, length same as MacHashSize
                // - IV: initialization vector, length blockSize
                byte[] output = new Byte[keySalt.Length + mac.Length + iv.Length + encryptedBytes.Length];

                // Copy data into new array
                Array.Copy(keySalt, 0, output, 0, keySalt.Length);
                Array.Copy(mac, 0, output, keySalt.Length, mac.Length);
                Array.Copy(iv, 0, output, (keySalt.Length + mac.Length), iv.Length);
                Array.Copy(encryptedBytes, 0, output, (keySalt.Length + mac.Length + iv.Length), encryptedBytes.Length);

                encryptedText = Convert.ToBase64String(output);

                return encryptedText;
            }
        }

        public static string Decrypt(byte[] cipherText, string key)
        {
            byte[] allBytes = cipherText;
            byte[] keyByteArray = ToByteArray(key);
            string plainText = null;

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // get the key salt
                byte[] keySalt = new byte[KeySize / 8];
                Array.Copy(allBytes, keySalt, keySalt.Length);

                // hash key with keysalt and original key
                byte[] prKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, keyByteArray, (KeySize / 8), keySalt);

                // if we want to verify the mac hash this is where we would do it.
                // Yii2 encryption data.
                // $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
                //
                //$authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
                //hashed = $this->hashData($iv. $encrypted, $authKey);
                //hashed = [macHash][data]

                // get the MAC code
                byte[] MAC = new byte[MacHashSize];
                Array.Copy(allBytes, keySalt.Length, MAC, 0, MAC.Length);

                // get our IV
                byte[] iv = new byte[BlockSize / 8];
                Array.Copy(allBytes, (keySalt.Length + MAC.Length), iv, 0, iv.Length);

                // get the data we need to decrypt
                byte[] cipherBytes = new byte[allBytes.Length - iv.Length - MAC.Length - keySalt.Length];
                Array.Copy(allBytes, (keySalt.Length + MAC.Length + iv.Length), cipherBytes, 0, cipherBytes.Length);

                // Create a decrytor to perform the stream transform.
                var decryptor = aes.CreateDecryptor(prKey, iv);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            //Read the decrypted bytes from the decrypting stream and place them in a string.
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plainText;
        }

        public static byte[] ToByteArray(string value)
        {
            byte[] allBytes = new byte[value.Length];
            int i = 0;
            foreach (byte bite in value)
            {
                allBytes[i] = Convert.ToByte(bite);
                i++;
            }

            return allBytes;
        }

        public static byte[] GenerateRandomBytes(int length = 32)
        {
            Random rnd = new Random();
            Byte[] bytes = new Byte[length];
            rnd.NextBytes(bytes);

            return bytes;
        }

        public static string HashData(byte[] iv, byte[] data, byte[] key)
        {
            byte[] combined = new byte[iv.Length + data.Length];
            Array.Copy(iv, combined, iv.Length);
            Array.Copy(data, 0, combined, iv.Length, data.Length);
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] hashed = hmac.ComputeHash(combined);
            var output = String.Concat(Array.ConvertAll(hashed, x => x.ToString("x2")));

            return output;
        }

        public static byte[] TestData()
        {
            var key = new ASCIIEncoding().GetBytes("the shared secret key here");
            var message = new ASCIIEncoding().GetBytes("the message to hash here");
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] output = hmac.ComputeHash(message);

            // to lowercase hexits
            var something = String.Concat(Array.ConvertAll(output, x => x.ToString("x2")));
            var testoutput = Convert.ToBase64String(output);
            byte[] test2 = ToByteArray(testoutput);
            return output;
        }
    }
}