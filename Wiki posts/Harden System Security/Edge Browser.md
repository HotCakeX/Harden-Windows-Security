# Edge Browser | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Edge%20Browser/Edge%20Browser.svg" alt="Edge Browser configurations - Harden Windows Security GitHub repository" width="500"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Block 3rd party cookies](https://learn.microsoft.com/deployedge/microsoft-edge-policies#blockthirdpartycookies) - Recommendatory policy

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Set Edge to use system's DNS over HTTPS](https://learn.microsoft.com/deployedge/microsoft-edge-policies#control-the-mode-of-dns-over-https)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Enable Encrypted Client Hello](https://learn.microsoft.com/deployedge/microsoft-edge-policies#encryptedclienthelloenabled)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Disable Basic HTTP authentication scheme](https://learn.microsoft.com/deployedge/microsoft-edge-policies#basicauthoverhttpenabled)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Allow devices using this hardening category to receive new features and experimentations like normal devices](https://learn.microsoft.com/deployedge/microsoft-edge-policies#control-communication-with-the-experimentation-and-configuration-service)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Enforce the audio process to run sandboxed](https://learn.microsoft.com/deployedge/microsoft-edge-policies#allow-the-audio-sandbox-to-run)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Sets the share additional operating system region setting to never](https://learn.microsoft.com/deployedge/microsoft-edge-policies#set-the-default-share-additional-operating-system-region-setting) - Recommendatory policy

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Disables the following weak Cipher Suites](https://learn.microsoft.com/DeployEdge/microsoft-edge-policies#tlsciphersuitedenylist)

    - [Site 1 to test TLS in your browser](https://clienttest.ssllabs.com:8443/ssltest/viewMyClient.html)

    - [Site 2 to test TLS in your browser](https://browserleaks.com/tls)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Policy](https://learn.microsoft.com/DeployEdge/microsoft-edge-policies#defaultwindowmanagementsetting) that automatically denies the window management permission to sites by default. This limits the ability of sites to see information about the device's screens and use that information to open and place windows or request fullscreen on specific screens.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Policy](https://learn.microsoft.com/DeployEdge/microsoft-edge-policies#defaultwebusbguardsetting) that will prevent websites from even requesting access to the local connected USB devices.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Policy](https://learn.microsoft.com/DeployEdge/microsoft-edge-policies#dynamiccodesettings) that will disable dynamic code in Edge browser which is a security feature that prevents the browser process from creating dynamic code. The default value of this policy is not explicitly defined, it could be enabled or could be disabled. Setting it explicitly to enabled via this policy ensures that no dynamic code is created by the browser process.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="25" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/deployedge/configure-edge-with-mdm)

```
TLS_RSA_WITH_AES_256_CBC_SHA  Reason: NO Perfect Forward Secrecy, CBC, SHA1
TLS_RSA_WITH_AES_128_CBC_SHA  Reason: NO Perfect Forward Secrecy, CBC, SHA1
TLS_RSA_WITH_AES_128_GCM_SHA256  Reason: NO Perfect Forward Secrecy
TLS_RSA_WITH_AES_256_GCM_SHA384  Reason: NO Perfect Forward Secrecy
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA  Reason: CBC, SHA1
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  Reason: CBC, SHA1
```

<br>

Due to security reasons, many policies cannot be used when you are signed into Edge browser using personal Microsoft account. [This app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) does not use any of those policies. When those policies are applied, they are ignored by the browser and `edge://policy/` shows an error for them.

<br>

* You can view all of the policies being applied to your Edge browser by visiting this page: `edge://policy/`
* You can find all of the available internal Edge pages in here: `edge://about/`

<br>

- Useful links:
    - [Microsoft Edge stable channel change log](https://learn.microsoft.com/deployedge/microsoft-edge-relnote-stable-channel)
    - [Microsoft Edge Security updates change log](https://learn.microsoft.com/deployedge/microsoft-edge-relnotes-security)
    - [Microsoft Edge Beta channel change log](https://learn.microsoft.com/deployedge/microsoft-edge-relnote-beta-channel)
    - [Microsoft Edge Mobile stable channel change log](https://learn.microsoft.com/deployedge/microsoft-edge-relnote-mobile-stable-channel)
    - [Edge Insider for Beta/Dev/Canary channels](https://www.microsoft.com/en-us/edge/download/insider)
    - [Microsoft Edge Security baselines](https://www.microsoft.com/en-us/download/details.aspx?id=55319) - Work without ingesting [ADMX policy files](https://www.microsoft.com/en-us/edge/business/download) first
        - [Reason why this app doesn't use it.](https://github.com/HotCakeX/Harden-Windows-Security/issues/50)

<br>
