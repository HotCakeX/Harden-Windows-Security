# Application Control (WDAC) Frequently Asked Questions (FAQs)

## What's The Difference Between Application Control Policies And An Antivirus?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%E2%80%99s%20The%20Difference%20Between%20Application%20Control%20Policies%20And%20An%20Antivirus.png" alt="What's The Difference Between Application Control Policies And An Antivirus">

<br>

Application Control policies are based on whitelisting strategy, meaning everything is blocked by default unless explicitly allowed. Antiviruses on the other hand are based on blacklisting strategy, meaning everything is allowed by default unless explicitly blocked.

<br>

## Can I Use Microsoft Defender For Endpoint (MDE) To Collect WDAC Logs?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/Can%20I%20Use%20Microsoft%20Defender%20For%20Endpoint%20(MDE)%20To%20Collect%20WDAC%20Logs.png" alt="Can I Use Microsoft Defender For Endpoint (MDE) To Collect WDAC Logs">

<br>

Yes. [MDE Should definitely be used](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control) to manage your endpoints and collect Code Integrity logs used to create WDAC policies. They provide very detailed CI info at scale for your entire fleet of machines. Then Intune can be used for at scale deployment of the policies after creation.

<br>

## Can Supplemental Policies Have Deny Rules?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/Can%20Supplemental%20Policies%20Have%20Deny%20Rules.png" alt="Can Supplemental Policies Have Deny Rules">

<br>

No, Supplemental policies are only used to expand a base policy by allowing more files.

<br>

## How Can I Make My WDAC Policy Tamper Proof?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Can%20I%20Make%20My%20WDAC%20Policy%20Tamper%20Proof.png" alt="How Can I Make My WDAC Policy Tamper Proof">

<br>

If you cryptographically sign and deploy your WDAC policy, it will be tamper-proof and even the system administrator won't be able to remove it without the certificate's private keys 🔑.

<br>

## How Do Enterprises And Businesses Use Application Control (WDAC)?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Do%20Enterprises%20And%20Businesses%20Use%20Application%20Control%20(WDAC).png" alt="How Do Enterprises And Businesses Use Application Control (WDAC)">

<br>

Businesses and Enterprises have a variety of options. They can set Intune as Managed Installer so any application pushed by the administrator to the endpoints will be trusted and installed but the users won't be able to install new applications on their own.

<br>

## How Many WDAC Policies Can Be Deployed On a System?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Many%20WDAC%20Policies%20Can%20be%20deployed%20on%20a%20sytem.png" alt="How Many WDAC Policies Can Be Deployed On a System">

<br>

There is no limit on how many Application Control (WDAC) policies you can deploy on a system.

<br>

## What Are The Tools I Need To Get Started With Application Control (WDAC) Policies?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Are%20The%20Tools%20I%20Need%20To%20Get%20Started%20With%20Application%20Control%20(WDAC)%20Policies.png" alt="What Are The Tools I Need To Get Started With Application Control (WDAC) Policies">

<br>

[WDACConfig PowerShell module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) and [WDAC Wizard](https://webapp-wdac-wizard.azurewebsites.net/) are all you need to begin your Application Control journey and create a robust security policy for your environment. They provide many advanced features that you can explore further when you're ready.

<br>

## What Is ISG And How Can I Use It In An Application Control (WDAC) Policy?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20ISG%20And%20How%20Can%20I%20Use%20It%20In%20An%20Application%20Control%20(WDAC)%20Policy.png" alt="What Is ISG And How Can I Use It In An Application Control (WDAC) Policy">

<br>

ISG stands for [The Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/use-wdac-with-intelligent-security-graph). It's a very powerful AI-based system that processes Trillions of signals from all kinds of data sources every day. You can utilize it as the arbiter in WDAC policies so it can help you allow trusted apps and block unknown or malicious apps automatically.

<br>

## What Is Smart App Control?

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20Smart%20App%20Control.png" alt="What Is Smart App Control">

Smart App Control is an automated AI-based Application Control mechanism that uses the same underlying components as WDAC (Windows Defender Application Control). It can be used in all Windows editions and provides great level of security by default for all systems it's enabled on.

<br>

## What Is The Most Secure Level To Use For Authorizing Files?

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20The%20Most%20Secure%20Level%20To%20Use%20For%20Authorizing%20Files.png" alt="What Is The Most Secure Level To Use For Authorizing Files">

For signed files, you should always use `WHQLFilePublisher` as [main level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) and `FilePublisher` as fallback. For unsigned files, use `Hash` level.

<br>
