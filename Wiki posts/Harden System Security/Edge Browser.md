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

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> [Policy](https://learn.microsoft.com/DeployEdge/microsoft-edge-policies#dynamiccodesettings) that will disable dynamic code in Edge browser which is a security feature that prevents the browser process from creating dynamic code. The default value of this policy is not explicitly defined, it could be enabled or could be disabled. Setting it explicitly to enabled via this policy ensures that no dynamic code is created by the browser process.

    * Please view this related conversation about this security measure: https://github.com/HotCakeX/Harden-Windows-Security/issues/1160

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables [Enhanced security mode](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-security-browse-safer) in Microsoft Edge mitigates memory-related vulnerabilities by disabling just-in-time (JIT) JavaScript compilation and enabling additional operating system protections for the browser.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> [Prevents](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/defaultlocalfontssetting) websites from accessing information about locally installed fonts.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Makes sure that only [Microsoft signed binaries](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/browsercodeintegritysetting) are allowed to load in the Edge process by enabling Code Integrity for Edge.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> [Restricts](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies/restrictcoresharingonrenderer) CPU core sharing for renderer process. Helps mitigate side-channel cross-process memory attacks by isolating the renderer process to a dedicated CPU core, preventing other processes from being scheduled on the same core.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Launches [Renderer processes](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies/rendererappcontainerenabled) into an App Container for more security benefits.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Microsoft Edge will prefer [the algorithms](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies/preferslowkexalgorithms) required for the Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) for TLS 1.3 and QUIC connections.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Configures Microsoft Edge to prefer [ciphers](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies/preferslowciphers) required for compliance with the Commercial National Security Algorithm Suite versions 1.0 and 2.0 (CNSA 1.0 and 2.0). Only affects TLS 1.3 and QUIC.

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
    - [Microsoft Edge Security baselines](https://www.microsoft.com/en-us/download/details.aspx?id=55319) work without ingesting [ADMX policy files](https://www.microsoft.com/en-us/edge/business/download) first.
        - **You can apply them via the [Harden System Security app](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Microsoft-Security-Baselines#microsoft-edge-security-baseline)**.

<br>

## Management

The **Management** tab provides direct controls for Microsoft Edge settings that you may want to configure independently of the recommended security measures above.

### [DNS over HTTPS Mode](https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode)

Use **DNS over HTTPS mode** to control how Microsoft Edge uses secure DNS. The available modes are:

* **`automatic`**: Edge uses DNS over HTTPS when possible and can fall back to regular, unencrypted DNS when necessary.
* **`secure`**: Edge uses DNS over HTTPS without falling back to regular DNS. Configure a valid DNS over HTTPS template before using this mode.
* **`off`**: Disables DNS over HTTPS in Edge.

### [DNS over HTTPS Templates](https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/dnsoverhttpstemplates)

Use **DNS over HTTPS resolver templates** to configure the DoH server or servers that Microsoft Edge should use. You can enter one or more HTTPS URI templates. This is useful when you want Edge to use a custom DoH provider or a DNS over HTTPS server that you host yourself, including the local DoH server available on the app's [DNS](https://github.com/HotCakeX/Harden-Windows-Security/wiki/DNS) page.

When using **`secure`** mode, at least one DoH template must be configured. If the templates field is left empty when using another mode, the corresponding `DnsOverHttpsTemplates` policy is removed.

### Refresh and Apply

* **Refresh**: Reads the currently configured Edge DNS over HTTPS policies and fills the controls with their current values. The same refresh happens automatically whenever you switch to the **Management** tab.
* **Apply**: Saves the selected DNS over HTTPS mode and templates to the Microsoft Edge machine policies.

> [!TIP]
> You can inspect the policies currently loaded by Microsoft Edge by entering `edge://policy/` in the Edge address bar. If you recently changed a policy, use the **Reload policies** button on that page to ask Edge to reload its policies immediately.
