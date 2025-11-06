# Script Enforcement and PowerShell Constrained Language Mode in App Control Policies

## Introduction

This article explores some of the technical details of how to deploy an App Control policy that uses Script Enforcement and forces PowerShell to run in Constrained Language Mode. It expands aspects of this topic that are not covered enough in the official docs.

> [!Tip]\
> Check out these 2 documents from Microsoft for more info and basics:
>
> * [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)
>
> * [Script enforcement with App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement)

<br>

Below are the required steps to enable Script Enforcement and allow a PowerShell module to run in Constrained Language Mode, if its code meets the requirements of it.

<br>

## Signing the PowerShell Module files

The PowerShell module that you intend to use in Constrained Language Mode must be completely signed, that means all of its `.psm1` and `.psd1` files must be signed by a code signing certificate.

<br>

## Type of Certificate to Use to Sign the PowerShell Module Files

The Code Signing certificate you're going to use to sign the PowerShell module files with can be a self-signed certificate or a certificate from a trusted certification authority (CA).

<br>

## Making the System Trust the Certificate

If the certificate you used to sign the PowerShell module files with is from a trusted certification authority (CA) and the root certificate of that CA exists in the "Trusted Root Certification Authorities" store of ***either the Local Machine or Current User certificate store***, then you're good to go, but if the certificate is self-signed, you need to add the certificate's root certificate to either of those locations.

For instance, if you generated a Code Signing certificate from Windows Server Active Directory Certificate Services, and you used that certificate to sign the PowerShell module files, you need to export the root certificate containing the public key, to a `.cer` file and then add it to one of the locations mentioned earlier. Adding the leaf certificate, which is the one you used to sign the module files with, to those locations, will not count and won't allow the signed PowerShell module to run in Constrained Language Mode.

<br>

## Base Policy Requirements

The App Control base policy you're going to deploy must have `0 Enabled:UMCI` and it must not have the `11 Disabled:Script Enforcement` [rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options).

<br>

## How to Create a Supplemental Policy to Allow the Certificate(s)

The root certificate's details must be added as a Signer rule in an App Control policy in the User-Mode Signing Scenario.

Adding the Certificate's Signer rule to the Kernel-mode Signing Scenario does not allow the modules signed by that certificate to run, which is expected.

For better management, you should allow the certificate in a new supplemental policy.

Here is an example of a valid Supplemental policy that allows a root certificate as a signer.

```xml
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Supplemental Policy">
  <VersionEx>1.0.0.0</VersionEx>
  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
  <Rules>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
  </Rules>
  <EKUs />
  <FileRules />
  <Signers>
    <Signer ID="ID_SIGNER_S_1_1" Name="Root Certificate">
      <CertRoot Type="TBS" Value="e3fbf9a3dc3022eab22b5e961bc6fee45782ae8aaed1d8402f2101a5f393db876444ef1d0e302f03b64463bae816f701cc5cda41068a8bf1954a0cd262eb9d6f" />
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Auto generated policy on 04-26-2024">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 04-26-2024">
      <ProductSigners>
        <AllowedSigners>
          <AllowedSigner SignerId="ID_SIGNER_S_1_1" />
        </AllowedSigners>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
    <CiSigners>
  <CiSigner SignerId="ID_SIGNER_S_1_1" />
  </CiSigners>
  <HvciOptions>2</HvciOptions>
  <BasePolicyID>{7558D4BF-69E3-45CA-9C52-915E48A7C50E}</BasePolicyID>
  <PolicyID>{32C551AF-C243-477A-9955-D37EDF435414}</PolicyID>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value>
        <String>Supplemental Policy</String>
      </Value>
    </Setting>
  </Settings>
</SiPolicy>
```

As you can see, we need the TBS Hash value of the root certificate.

<br>

### Use the AppControl Manager to Automatically Allow Certificates

You can use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create a supplemental policy that allows the certificates you select to be allowed by App Control.

***[Refer to this page for more information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy#create-a-supplemental-policy-from-certificate-files)***

<br>


> [!TIP]\
> A manual way to get the TBS Hash value of a certificate is using the following command, which also works for signed files and will show the details of the certificates in the chain as well.
>
> ```powershell
> certutil.exe -v <Path To .cer file>
> ```
>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/Screenshot%20TBS%20Hash%20CertUtil.png" alt="TBS Hash value using certutil.exe -v">

<br>

## PowerShell Engine Behavior

When an App Control policy with script enforcement is deployed and you try to import an unauthorized module, you might see different errors. For instance, you might see an error about classes not being allowed or other reasons for a module not being able to load, but in essence, the PowerShell engine is trying to load the module in Constrained Language Mode and the module is failing to meet the requirements, most likely because:

* The module you're trying to load is not signed
* The module you're trying to load is signed but the certificate's root is not trusted by the system
* The module you're trying to load is signed but at least one of its files is tampered with and has a hash mismatch. Even adding a single space on an empty line causes hash mismatch, **which is expected**.

<br>
