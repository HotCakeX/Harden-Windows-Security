using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;

namespace WDACConfig.Pages
{
    public sealed partial class MicrosoftDocumentation : Page
    {
        public MicrosoftDocumentation()
        {
            this.InitializeComponent();
            // Set background color of WebView2 while content is loading
            MicrosoftDocumentationWebView2.DefaultBackgroundColor = Colors.Black;

            // Handle navigation events to manage button state
            MicrosoftDocumentationWebView2.NavigationCompleted += WebView2_NavigationCompleted;

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        // Event handler for Back button
        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            if (MicrosoftDocumentationWebView2.CanGoBack)
            {
                MicrosoftDocumentationWebView2.GoBack();
            }
        }

        // Event handler for Forward button
        private void ForwardButton_Click(object sender, RoutedEventArgs e)
        {
            if (MicrosoftDocumentationWebView2.CanGoForward)
            {
                MicrosoftDocumentationWebView2.GoForward();
            }
        }

        // Event handler for Reload button
        private void ReloadButton_Click(object sender, RoutedEventArgs e)
        {
            MicrosoftDocumentationWebView2.Reload();
        }

        // Event handler for Home button
        private void HomeButton_Click(object sender, RoutedEventArgs e)
        {
            MicrosoftDocumentationWebView2.Source = new Uri("https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol");
        }

        // Update the state of navigation buttons when navigation is completed so that the Back/Forward buttons will be enabled only when they can be used
        private void WebView2_NavigationCompleted(object sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs e)
        {
            // The following checks are required to prevent any errors when intentionally spam navigating between pages and elements extremely fast
            try
            {
                // Check if the WebView2 control or its CoreWebView2 instance is disposed
                if (MicrosoftDocumentationWebView2 != null && MicrosoftDocumentationWebView2.CoreWebView2 != null)
                {
                    BackButton.IsEnabled = MicrosoftDocumentationWebView2.CanGoBack;
                    ForwardButton.IsEnabled = MicrosoftDocumentationWebView2.CanGoForward;
                }
            }

            catch (ObjectDisposedException ex)
            {
                // Log the exception, but avoid crashing the app
                System.Diagnostics.Debug.WriteLine("WebView2 in Microsoft Documentation page has been disposed: " + ex.Message);
            }
        }
    }
}
