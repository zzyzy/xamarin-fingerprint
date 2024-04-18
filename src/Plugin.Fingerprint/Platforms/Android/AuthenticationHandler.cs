using System.Threading.Tasks;
using Android.Content;
using Java.Lang;
using Plugin.Fingerprint.Abstractions;
using AndroidX.Biometric;
using Plugin.Fingerprint.Utils;

namespace Plugin.Fingerprint
{
    public class AuthenticationHandler : BiometricPrompt.AuthenticationCallback, IDialogInterfaceOnClickListener
    {
        private readonly TaskCompletionSource<FingerprintAuthenticationResult> _taskCompletionSource;
        private readonly SecureBiometricPromptContext _secureContext;

        public AuthenticationHandler(SecureBiometricPromptContext secureContext)
        {
            _taskCompletionSource = new TaskCompletionSource<FingerprintAuthenticationResult>();
            _secureContext = secureContext;
        }

        public Task<FingerprintAuthenticationResult> GetTask()
        {
            return _taskCompletionSource.Task;
        }

        private void SetResultSafe(FingerprintAuthenticationResult result)
        {
            if (!(_taskCompletionSource.Task.IsCanceled || _taskCompletionSource.Task.IsCompleted || _taskCompletionSource.Task.IsFaulted))
            {
                _taskCompletionSource.SetResult(result);
            }
        }

        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
        {
            base.OnAuthenticationSucceeded(result);

            var isValid = CryptoUtils.ValidateSecret(result, _secureContext);
            var faResult = new FingerprintAuthenticationResult
            {
                Status = isValid 
                    ? FingerprintAuthenticationResultStatus.Succeeded 
                    : FingerprintAuthenticationResultStatus.Failed
            };
            _taskCompletionSource.TrySetResult(faResult);
        }

        public override void OnAuthenticationError(int errorCode, ICharSequence errString)
        {
            base.OnAuthenticationError(errorCode, errString);

            var message = errString != null ? errString.ToString() : string.Empty;
            var result = new FingerprintAuthenticationResult { Status = FingerprintAuthenticationResultStatus.Failed, ErrorMessage = message };

            result.Status = errorCode switch
            {
                BiometricPrompt.ErrorLockout => FingerprintAuthenticationResultStatus.TooManyAttempts,
                BiometricPrompt.ErrorUserCanceled => FingerprintAuthenticationResultStatus.Canceled,
                BiometricPrompt.ErrorNegativeButton => FingerprintAuthenticationResultStatus.Canceled,
                _ => FingerprintAuthenticationResultStatus.Failed
            };

            SetResultSafe(result);
        }

        public override void OnAuthenticationFailed()
        {
            base.OnAuthenticationFailed();
        }

        public void OnClick(IDialogInterface dialog, int which)
        {
            var faResult = new FingerprintAuthenticationResult { Status = FingerprintAuthenticationResultStatus.Canceled };
            SetResultSafe(faResult);
        }

        //public override void OnAuthenticationHelp(BiometricAcquiredStatus helpCode, ICharSequence helpString)
        //{
        //    base.OnAuthenticationHelp(helpCode, helpString);
        //    _listener?.OnHelp(FingerprintAuthenticationHelp.MovedTooFast, helpString?.ToString());
        //}
    }
}