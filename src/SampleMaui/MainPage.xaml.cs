using Plugin.Fingerprint;
using Plugin.Fingerprint.Abstractions;

namespace SampleMaui;

public partial class MainPage : ContentPage
{
    public MainPage()
    {
        InitializeComponent();
    }

    private async void BtnAuthenticate_OnClicked(object? sender, EventArgs e)
    {
        if (IsBusy) return;
        IsBusy = true;

        try
        {
            var request = new AuthenticationRequestConfiguration("Biometrics", "Confirm biometrics to continue");
            var result = await CrossFingerprint.Current.AuthenticateAsync(request);

            await DisplayAlert(
                result.Status == FingerprintAuthenticationResultStatus.Succeeded
                    ? "Success"
                    : "Failed",
                result.Status == FingerprintAuthenticationResultStatus.Succeeded
                    ? "Auth Success"
                    : "Auth Failed",
                "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Exception", ex.ToString(), "OK");
        }
        finally
        {
            IsBusy = false;
        }
    }
}