#nullable enable
// ReSharper disable CheckNamespace

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Android.OS;
using Android.Security.Keystore;
using AndroidX.Biometric;
using Java.Security;
using Java.Security.Spec;
using Javax.Crypto;
using Javax.Crypto.Spec;
using CipherMode = Javax.Crypto.CipherMode;

namespace Plugin.Fingerprint.Utils
{
    internal static class CryptoUtils
    {
        private const string KeyName = "11aa594e-a644-4f00-8695-1bd72aaa2baf-my-app-biometric-key-name";

        public static async Task<SecureBiometricPromptContext> InitializeAsync()
        {
            // Generate asymmetric key so that we can use the public key to encrypt the randomly generated
            // secret. After authentication, the private key will be used to decrypt the secret and validated.
            var encryptionKey = GetEncryptionKey(KeyName)
                                ?? await Task.Run(() => GenerateSecretKey(KeyName));
            var encryptionCipher = GetCipher();

            // https://stackoverflow.com/questions/36015194/android-keystoreexception-unknown-error
            var oaepParameterSpec =
                new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.Sha1,
                    PSource.PSpecified.Default);
            encryptionCipher.Init(CipherMode.EncryptMode, encryptionKey, oaepParameterSpec);

            var secret = GenerateSecret();
            var encryptedSecret = encryptionCipher.DoFinal(secret)!;

            var decryptionKey = GetDecryptionKey(KeyName);
            var decryptionCipher = GetCipher();
            decryptionCipher.Init(CipherMode.DecryptMode, decryptionKey, oaepParameterSpec);

            var context = new SecureBiometricPromptContext(
                secret,
                encryptedSecret,
                decryptionCipher);
            return context;
        }

        public static bool ValidateSecret(
            BiometricPrompt.AuthenticationResult result,
            SecureBiometricPromptContext secureContext)
        {
            var cipher = result.CryptoObject?.Cipher ?? throw new InvalidOperationException();
            var encryptedSecret = secureContext.EncryptedSecret;
            var expectedSecret = secureContext.Secret;
            var actualSecret = cipher.DoFinal(encryptedSecret)!;
            var isValid = actualSecret.SequenceEqual(expectedSecret);
            return isValid;
        }

        private static byte[] GenerateSecret()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[16];
                rng.GetBytes(bytes);
                return bytes;
            }
        }

        private static IKey GenerateSecretKey(string keyName)
        {
            try
            {
                return GenerateSecretKeyInternal(CreateKeyGenParameterSpec(keyName));
            }
            catch (StrongBoxUnavailableException)
            {
                return GenerateSecretKeyInternal(CreateKeyGenParameterSpec(keyName, false));
            }
        }

        private static IKey GenerateSecretKeyInternal(KeyGenParameterSpec keyGenParameterSpec)
        {
            var kpg = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa, "AndroidKeyStore")
                      ?? throw new InvalidOperationException();
            kpg.Initialize(keyGenParameterSpec);
            var kp = kpg.GenerateKeyPair()
                     ?? throw new InvalidOperationException();

            // Return the public key here because we will be
            // using it for encryption right after this method
            //
            // Returning private key throws exception when initializing the Cipher object
            //
            var publicKey = kp.Public ?? throw new InvalidOperationException();
            return publicKey;
        }

        private static IKey? GetEncryptionKey(string keyName)
        {
            var ks = KeyStore.GetInstance("AndroidKeyStore") ?? throw new InvalidOperationException();
            // Before the keystore can be accessed, it must be loaded.
            ks.Load(null);

            var publicKey = ks.GetCertificate(keyName)?.PublicKey;
            return publicKey;
        }

        private static IKey? GetDecryptionKey(string keyName)
        {
            var ks = KeyStore.GetInstance("AndroidKeyStore") ?? throw new InvalidOperationException();
            // Before the keystore can be accessed, it must be loaded.
            ks.Load(null);

            var entry = ks.GetEntry(keyName, null) as KeyStore.PrivateKeyEntry;
            var privateKey = entry?.PrivateKey;
            return privateKey;
        }

        private static Cipher GetCipher()
        {
            // https://developer.android.com/reference/javax/crypto/Cipher
            return Cipher.GetInstance(KeyProperties.KeyAlgorithmRsa + "/"
                                                                    + "NONE" + "/"
                                                                    + "OAEPwithSHA-256andMGF1Padding")
                   ?? throw new InvalidOperationException();
        }

        // https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec
        // https://developer.android.com/privacy-and-security/keystore#UserAuthentication
        private static KeyGenParameterSpec CreateKeyGenParameterSpec(string keyName,
            bool useStrongBox = true)
        {
            var builder = new KeyGenParameterSpec.Builder(
                    keyName,
                    KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetKeySize(4096)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingRsaOaep)
                .SetDigests(KeyProperties.DigestSha256)
                .SetUserAuthenticationRequired(true);

#if NET
        if (OperatingSystem.IsAndroidVersionAtLeast(30))
#else
            if (Build.VERSION.SdkInt >= BuildVersionCodes.R)
#endif
            {
                builder = builder
                    .SetUserAuthenticationParameters(0, (int)KeyPropertiesAuthType.BiometricStrong);
                // builder = builder
                //     .SetUserAuthenticationParameters(0, (int)(KeyPropertiesAuthType.BiometricStrong |
                //                                               KeyPropertiesAuthType.DeviceCredential));
            }

            // Invalidate the keys if the user has registered a new biometric
            // credential, such as a new fingerprint. Can call this method only
            // on Android 7.0 (API level 24) or higher. The variable
            // "invalidatedByBiometricEnrollment" is true by default.
            if (Build.VERSION.SdkInt >= BuildVersionCodes.N)
            {
                builder = builder.SetInvalidatedByBiometricEnrollment(true);
            }

            if (Build.VERSION.SdkInt >= BuildVersionCodes.P)
            {
                builder = builder.SetIsStrongBoxBacked(useStrongBox);

                if (useStrongBox)
                {
                    // StrongBox does not support 4096 key size
                    // Throws "unsupported key size (internal Keystore code: -6 message: In generate_key...)"
                    builder = builder.SetKeySize(2048);
                }
            }

            return builder.Build();
        }
    }

    public sealed class SecureBiometricPromptContext
    {
        public byte[] Secret { get; }

        public byte[] EncryptedSecret { get; }

        public Cipher DecryptionCipher { get; }

        public SecureBiometricPromptContext(
            byte[] secret,
            byte[] encryptedSecret,
            Cipher decryptionCipher)
        {
            Secret = secret;
            EncryptedSecret = encryptedSecret;
            DecryptionCipher = decryptionCipher;
        }
    }
}