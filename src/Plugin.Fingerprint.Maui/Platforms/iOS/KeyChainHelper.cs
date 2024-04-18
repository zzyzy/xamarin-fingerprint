#nullable enable

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using Security;

// ReSharper disable CheckNamespace

namespace Plugin.Fingerprint
{
    internal static class KeyChainHelper
    {
        private const string KeyName = "11aa594e-a644-4f00-8695-1bd72aaa2baf-my-app-biometric-key-name";

        public static Task<Tuple<bool, NSError?>> AuthenticateAsync(LAContext context)
        {
            var secret = GenerateSecret(KeyName, context);
            var actualSecret = GetSecret(KeyName, context);

            var isValid = actualSecret != null &&
                          actualSecret.SequenceEqual(secret);

            return Task.FromResult(Tuple.Create(isValid, (NSError?)null));
        }

        private static byte[] GenerateSecret(string keyName, LAContext context)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[16];
                rng.GetBytes(bytes);

                var base64 = Convert.ToBase64String(bytes);
                var access = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly,
                    flags: SecAccessControlCreateFlags.BiometryCurrentSet);
                var record = new SecRecord(SecKind.GenericPassword)
                {
                    Account = keyName,
                    ValueData = NSData.FromString(base64),
                    AccessControl = access,
                    AuthenticationContext = context,
                };

                var status = SecKeyChain.Add(record);
                if (status == SecStatusCode.AuthFailed)
                {
                    // Check if biometric setup already
                    throw new Exception("Biometric not setup");
                }
                else if (status == SecStatusCode.DuplicateItem)
                {
                    SecKeyChain.Remove(record);
                    status = SecKeyChain.Add(record);
                    if (status != SecStatusCode.Success)
                    {
                        throw new Exception(status.ToString());
                    }
                }

                return bytes;
            }
        }

        private static byte[]? GetSecret(string keyName, LAContext context)
        {
            var access = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly,
                flags: SecAccessControlCreateFlags.BiometryCurrentSet);
            var record = new SecRecord(SecKind.GenericPassword)
            {
                Account = keyName,
                AccessControl = access,
                AuthenticationContext = context,
            };

            // This will trigger biometric prompt dialog. 
            // The interaction between LocalAuthentication and Security is handled by iOS itself 
            // (and not within the app userspace), as such this will not be bypassed by objection or Frida.
            //
            // https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id
            var data = SecKeyChain.QueryAsData(record);
            if (data == null) return null;

            var base64 = data.ToString();
            var bytes = Convert.FromBase64String(base64);
            return bytes;
        }
    }
}