# App Control Policy for BYOVD Kernel Mode Only Protection

This scenario involves removing the trust to any Kernel mode driver, whether they are vulnerable or not. It does not affect User-mode binaries or drivers. Any 3rd party software/hardware Kernel mode driver will need to be explicitly allowed. This scenario protects against all **BYOVD** scenarios and much more.

Drivers can access the Kernel which is the core of the operating system. Microsoft requires all drivers to be digitally signed:

* Kernel mode Hardware drivers **need** to be signed with an EV (Extended Validation) certificate.
* Kernel mode Virtual drivers (such as virtual network adapters) **can** be signed with a non-EV certificate.

A BYOVD (Bring Your Own Vulnerable Driver) scenario involves exploiting one of the digitally signed drivers that harbors a security flaw to attain direct access to the core of the OS. **This attack vector applies to all OSes, not just Windows.**

People who seek to obtain code signing certificates, even for Extended Validation certificates, are not undergoing [proper verification](https://learn.microsoft.com/en-us/office365/servicedescriptions/office-365-platform-service-description/office-365-us-government/gcc-high-and-dod#background-screening).

* Kernel is the key to your kingdom.
* Do not waste your time playing cat and mouse with threat actors.
* Do not use blacklisting for highly secure workstations, sensitive environments and such; it’s ineffective and insecure for a high security level.
* Whitelisting is the proper answer. This entire document and others in this repository, are exactly for this purpose.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## There Are 3 Types of Kernel Mode Drivers That Can Run on Windows

### Regular drivers

A regular signed driver is a driver that has been digitally signed by the developer using a software publisher certificate (SPC) issued by a Microsoft approved Certificate Authority (CA).

These are regular signed Kernel mode drivers from 3rd parties that shouldn't be trusted by default in a secure and high-risk environment.

### WHQL drivers

A WHQL driver is a driver that has been tested and certified by Microsoft's Windows Hardware Quality Labs (WHQL). A WHQL driver has passed Microsoft's compatibility tests and can be distributed through Windows Update or other Microsoft-supported channels, while a regular signed driver may not have passed those tests and may not be eligible. A WHQL driver is signed by Microsoft.

WHQL drivers have a slightly higher security bar than regular Kernel mode drivers. Any driver updates are required to pass the WHQL testing too.

### EV Signed Drivers

EV signed kernel mode drivers are drivers that have been signed with an extended validation code signing certificate issued by a trusted certificate authority (CA).

EV certificates cost more than regular code signing certificates, they require to be on an HSM (to ensure the private key is stored properly) and CAs issuing them only validate that the company of the person requesting them exists. Anyone can get EV certificate as long as they have a HSM and a company, which is not hard to come by, costs about ~100$ to set up in the US as a resident.

Sometimes the issuing CA also needs you to send in your driver's license and a picture of you holding it, but things like extended background checks, criminal history check, nationality check, or [the proper checks explained in here](https://learn.microsoft.com/en-us/office365/servicedescriptions/office-365-platform-service-description/office-365-us-government/gcc-high-and-dod#background-screening) are not performed.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What Is the Solution?

We need to establish a Zero-Trust situation by eliminating the default trust to any signed driver and explicitly authorizing each driver that seeks to access the kernel.

Numerous applications incorporate drivers that interact with the Kernel. Ordinarily, they are unnoticeable, but if you deploy the App Control policy that we are going to create, in Audit mode, you will be able to observe event logs generated for each of the kernel-mode drivers.

By creating a strict kernel mode App Control policy, you will have a powerful security feature at your fingertips.

This approach is the kind of future-leading technology you need. You can't afford waiting for analysis to predict malicious behavior or wait for malware to be found and cataloged before something is done about it.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to make a strict Kernel mode App Control policy

We take the Default Windows example policy from `C:\Windows\schemas\CodeIntegrity\ExamplePolicies` and remove the following items from it:

### From the EKUs section

* `ID_EKU_WHQL` which is for [WHQL (Windows Hardware Quality Labs)](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/whql-release-signature), it allows 3rd party drivers that have WHQL certification to run, but since we are making a strict Kernel-mode App Control policy, we want to handpick which Kernel mode drivers get to run on the system.

* `"ID_EKU_RT_EXT"` belongs to Windows Runtime, Usermode only.

* `"ID_EKU_STORE"` for Microsoft Store apps, Usermode only.

* `"ID_EKU_DCODEGEN"` for .NET hardening [Dynamic Code Security](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-and-dotnet), user mode only, the linked document mentions it's Usermode too.

* `"ID_EKU_AM"` Usermode only.

  * `<EKU ID="ID_EKU_AM" FriendlyName="AntiMalware EKU -1.3.6.1.4.1.311.76.11.1 " Value="010a2b0601040182374c0b01" />`

  * EKU (Enhanced Key Usage) is a field in a digital certificate that specifies the purposes for which the certificate can be used.

  * The FriendlyName attribute of the EKU is a human-readable name that describes the purpose of the certificate. The FriendlyName also includes the Object Identifier (OID) of the certificate, which is a numeric code that identifies who issued the certificate and what it is for. The OID follows a hierarchical structure, where each dot-separated number represents a level of authority or category.

  * The Value attribute of the EKU, `010a2b0601040182374c0b01` is a hexadecimal representation of the OID, which is used by App Control to validate the certificate. The Value must match the OID exactly, otherwise App Control will not trust the certificate. It corresponds to the AntiMalware EKU certificate, which has an OID of `1.3.6.1.4.1.311.76.11.1`.

  * This certificate is used to verify files that are signed by an antimalware vendor whose product is using Protected Process Light (PPL). The AntiMalware EKU does not apply to kernel mode drivers, only to user mode processes that are signed by an antimalware vendor.

```xml
<EKU ID="ID_EKU_WHQL" Value="010A2B0601040182370A0305" />
<EKU ID="ID_EKU_RT_EXT" Value="010a2b0601040182370a0315" />
<EKU ID="ID_EKU_STORE" FriendlyName="Windows Store EKU - 1.3.6.1.4.1.311.76.3.1 Windows Store" Value="010a2b0601040182374c0301" />
<EKU ID="ID_EKU_DCODEGEN" FriendlyName="Dynamic Code Generation EKU - 1.3.6.1.4.1.311.76.5.1" Value="010A2B0601040182374C0501" />
<EKU ID="ID_EKU_AM" FriendlyName="AntiMalware EKU -1.3.6.1.4.1.311.76.11.1 " Value="010a2b0601040182374c0b01" />
```

<br>

<br>

For our strict Kernel-mode-only App Control policy, only the following EKUs are necessary

```xml
<EKUs>
    <EKU ID="ID_EKU_WINDOWS" Value="010A2B0601040182370A0306" FriendlyName="" />
    <EKU ID="ID_EKU_ELAM" Value="010A2B0601040182373D0401" FriendlyName="" />
    <EKU ID="ID_EKU_HAL_EXT" Value="010a2b0601040182373d0501" FriendlyName="" />
</EKUs>
```

<br>

### From the FileRules section

User Mode Refresh policy program

```xml
<FileAttrib ID="ID_FILEATTRIB_REFRESH_POLICY" FriendlyName="RefreshPolicy.exe FileAttribute" FileName="RefreshPolicy.exe" MinimumFileVersion="10.0.19042.0" />
```

<br>

### From the Signers section

* Any Signer with `_USER` in its ID indicating that it only applies to User Mode binaries/drivers

<br>

* Any Signer with `_RT` in its ID indicating that it belongs to Windows Runtime, which is User mode only.

```xml
<Signer ID="ID_SIGNER_RT_PRODUCTION" Name="Microsoft Product Root 2010 RT EKU">
    <CertRoot Type="Wellknown" Value="06" />
    <CertEKU ID="ID_EKU_RT_EXT" />
</Signer>
<Signer ID="ID_SIGNER_RT_FLIGHT" Name="Microsoft Flighting Root 2014 RT EKU">
    <CertRoot Type="Wellknown" Value="0E" />
    <CertEKU ID="ID_EKU_RT_EXT" />
</Signer>
<Signer ID="ID_SIGNER_RT_STANDARD" Name="Microsoft Standard Root 2011 RT EKU">
    <CertRoot Type="Wellknown" Value="07" />
    <CertEKU ID="ID_EKU_RT_EXT" />
</Signer>
```

<br>

* The following WHQL related Signers

  * These are the certificates that Microsoft uses to sign 3rd party OEM drivers

  * They are actually 1 certificate but in 3 different Hashing algorithms

```xml
<Signer ID="ID_SIGNER_WHQL_SHA2" Name="Microsoft Product Root 2010 WHQL EKU">
  <CertRoot Type="Wellknown" Value="06" />
  <CertEKU ID="ID_EKU_WHQL" />
</Signer>
<Signer ID="ID_SIGNER_WHQL_SHA1" Name="Microsoft Product Root WHQL EKU SHA1">
  <CertRoot Type="Wellknown" Value="05" />
  <CertEKU ID="ID_EKU_WHQL" />
</Signer>
<Signer ID="ID_SIGNER_WHQL_MD5" Name="Microsoft Product Root WHQL EKU MD5">
  <CertRoot Type="Wellknown" Value="04" />
  <CertEKU ID="ID_EKU_WHQL" />
</Signer>
```

<br>

* And this Signer which allows WHQL for insider builds

```xml
<Signer ID="ID_SIGNER_WHQL_FLIGHT_SHA2" Name="Microsoft Flighting Root 2014 WHQL EKU">
  <CertRoot Type="Wellknown" Value="0E" />
  <CertEKU ID="ID_EKU_WHQL" />
</Signer>
```

<br>

* Test Signer, for when [Driver signing test](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) is used, `Bcdedit.exe -set TESTSIGNING ON`

```xml
<Signer ID="ID_SIGNER_TEST2010" Name="MincryptKnownRootMicrosoftTestRoot2010">
<CertRoot Type="Wellknown" Value="0A" />
</Signer>
```

<br>

### From the SigningScenarios section

#### In the Kernel Mode Signing Scenario block

* Responsible for WHQL Signers we removed above

```xml
<AllowedSigner SignerId="ID_SIGNER_WHQL_SHA2" />
<AllowedSigner SignerId="ID_SIGNER_WHQL_SHA1" />
<AllowedSigner SignerId="ID_SIGNER_WHQL_MD5" />
```

<br>

* Responsible for insider builds WHQL signers

```xml
<AllowedSigner SignerId="ID_SIGNER_WHQL_FLIGHT_SHA2" />
```

<br>

* Responsible for Test Signer we removed above

```xml
<AllowedSigner SignerId="ID_SIGNER_TEST2010" />
```

<br>

#### In the User Mode Signing Scenario block

This entire block should either be removed

```xml
<!--User Mode Signing Scenario-->
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User Mode Signing Scenario">
  <ProductSigners>
    <AllowedSigners>
      <AllowedSigner SignerId="ID_SIGNER_WINDOWS_PRODUCTION_USER" />
      <AllowedSigner SignerId="ID_SIGNER_ELAM_PRODUCTION_USER" />
      <AllowedSigner SignerId="ID_SIGNER_HAL_PRODUCTION_USER" />
      <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA2_USER" />
      <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA1_USER" />
      <AllowedSigner SignerId="ID_SIGNER_WHQL_MD5_USER" />
      <AllowedSigner SignerId="ID_SIGNER_WINDOWS_FLIGHT_ROOT_USER" />
      <AllowedSigner SignerId="ID_SIGNER_ELAM_FLIGHT_USER" />
      <AllowedSigner SignerId="ID_SIGNER_HAL_FLIGHT_USER" />
      <AllowedSigner SignerId="ID_SIGNER_WHQL_FLIGHT_SHA2_USER" />
      <AllowedSigner SignerId="ID_SIGNER_STORE" />
      <AllowedSigner SignerId="ID_SIGNER_STORE_FLIGHT_ROOT" />
      <AllowedSigner SignerId="ID_SIGNER_RT_PRODUCTION" />
      <AllowedSigner SignerId="ID_SIGNER_DRM" />
      <AllowedSigner SignerId="ID_SIGNER_DCODEGEN" />
      <AllowedSigner SignerId="ID_SIGNER_AM" />
      <AllowedSigner SignerId="ID_SIGNER_RT_FLIGHT" />
      <AllowedSigner SignerId="ID_SIGNER_RT_STANDARD" />
      <AllowedSigner SignerId="ID_SIGNER_MICROSOFT_REFRESH_POLICY" />
      <!-- Test signer is trusted by ConfigCI, however, it will not be trusted by CI unless testsigning BCD is set -->
      <AllowedSigner SignerId="ID_SIGNER_TEST2010_USER" />
    </AllowedSigners>
  </ProductSigners>
</SigningScenario>
```

Or replaced with

```xml
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User Mode Signing Scenario">
  <ProductSigners />
</SigningScenario>
```

<br>

### Flight root signers - Optional

They can also be removed if you don't intend to use Windows insider builds. They all have `flight` or `_flight` in their ID.

When removing them, also use the [4 Disabled:Flight Signing policy rule option.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)

<br>

### From CiSigners

Remove this item which is for Windows Store EKU

```xml
<CiSigner SignerId="ID_SIGNER_STORE" />
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Use and Automate This Entire Process

> [!IMPORTANT]\
> **Use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Create-and-Maintain-Strict-Kernel%E2%80%90Mode-App-Control-Policy)** to automatically Audit and deploy the Strict Kernel-mode App Control policies.

As mentioned earlier, this policy only enforces and applies to Kernel-mode drivers, so your non-Kernel mode files are unaffected. Keep in mind that Kernel-mode does not mean programs that require Administrator privileges, those 2 categories are completely different. Also, not all drivers are Kernel mode, [**there are user-mode drivers too.**](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)

This strict Kernel mode policy can be perfectly deployed side by side any other App Control policy.

For instance, since HVCI is turned on by default on my system, the [Microsoft Recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) is automatically deployed and it's only Kernel mode. It has 2 allow all rules, making it primarily a block-list policy.

Then I deploy Strict Kernel-mode App Control policy, which also only applies to Kernel-mode drivers. It doesn't have allow all rules of course, instead it allows Windows components that are required for Windows to function properly to run and then will let you hand pick any 3rd party Kernel-mode drivers and easily allow them in your policy.

Now the Allow all rules that exist in the first policy are neutralized. [Only applications allowed by both policies run without generating block events.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies), so since the same allow all rules do not exist in our Strict Kernel-mode base policy, they no longer apply.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What About User-mode Binaries?

So far, we've only been doing Kernel-mode administration. We can use User-mode App Control policies as well.

After using those 2 Kernel-mode policies, we can deploy a 3rd policy which is going to authorize and validate User-mode binaries too, such as the [`Allow Microsoft` policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy). This policy applies to both Kernel and User mode files, but since we already know the logic and learned that only applications allowed by all base policies are allowed to run, we're confident that our Strict Kernel-mode base policy is the only one in charge of authorizing and validating Kernel-mode files/drivers.

<br>

### A rule of thumb

The strictest policy wins the race in multiple base policy deployments, which in this case is the Strict Kernel-Mode policy. Even though the `Allow Microsoft` policy allows all WHQL signed drivers, they still won't be able to run unless the Strict Kernel-Mode policy authorizes them as well, because for a Kernel driver to be allowed to run in this scenario, all base policies must allow it.

So only the policy that has the least allow listings in common with all other policies takes priority.

<br>

### Supplemental policy

Each of the deployed policies (except for the automatically deployed block rules by HVCI) support having supplemental policies. So, whenever you feel the need to allow additional files that are Kernel-mode drivers or User-mode binaries, you can add a Supplemental policy for them.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About ELAM (Early Launch Anti-Malware)

Anti-malware or antivirus vendors need to sign enforceable and binding legal agreements and develop an early launched anti-malware driver that Microsoft will sign. This driver includes a list of certificate hashes that enable that AV vendor to sign new versions without Microsoft’s involvement each time. When code integrity loads this ELAM driver, it permits any executables signed by the certificates in that list to run as anti-malware light.

* [Early Launch Anti-Malware Driver Sample](https://github.com/Microsoft/Windows-driver-samples/tree/main/security/elam)
* [ELAM Driver Requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img width="65" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/arrow-pink.gif" alt="Gif indicating Continue reading about important App Control notes"> [Continue reading about important App Control notes](#-continue-reading-about-important-wdac-notes)

#### [Important Notes and Tips](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes) about App Control policies

<br>
