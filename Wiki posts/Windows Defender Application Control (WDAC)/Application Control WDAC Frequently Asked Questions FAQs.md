# Application Control (WDAC) Frequently Asked Questions (FAQs)

## What's The Difference Between Application Control Policies And An Antivirus?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%E2%80%99s%20The%20Difference%20Between%20Application%20Control%20Policies%20And%20An%20Antivirus.png" alt="What's The Difference Between Application Control Policies And An Antivirus">

<br>

Application Control policies are based on whitelisting strategy, meaning everything is blocked by default unless explicitly allowed. Antiviruses on the other hand are based on blacklisting strategy, meaning everything is allowed by default unless explicitly blocked.

<br>

## How Does App Control In The OS Compare To 3rd Party Solutions?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Does%20WDAC%20In%20The%20OS%20Compare%20To%203rd%20Party%20Solutions.png" alt="How Does App Control In The OS Compare To 3rd Party Solutions">

<br>

App Control which is built deep inside of the OS kernel doesn’t need any “agents” to be installed, that means it can’t be killed using techniques used against 3rd party solutions, it also doesn’t increase the attack surface of the system. It’s native and exceedingly fast which makes it transparent to the user.

<br>

## Can I Use Microsoft Defender For Endpoint (MDE) To Collect App Control Logs?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/Can%20I%20Use%20Microsoft%20Defender%20For%20Endpoint%20(MDE)%20To%20Collect%20WDAC%20Logs.png" alt="Can I Use Microsoft Defender For Endpoint (MDE) To Collect App Control Logs">

<br>

Yes. [MDE Should definitely be used](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control) to manage your endpoints and collect Code Integrity logs used to create App Control policies. They provide very detailed CI info at scale for your entire fleet of machines. Then Intune can be used for at scale deployment of the policies after creation.

<br>

## Can Supplemental Policies Have Deny Rules?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/Can%20Supplemental%20Policies%20Have%20Deny%20Rules.png" alt="Can Supplemental Policies Have Deny Rules">

<br>

No, Supplemental policies are only used to expand a base policy by allowing more files.

<br>

## How Can I Make My App Control Policy Tamper Proof?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Can%20I%20Make%20My%20WDAC%20Policy%20Tamper%20Proof.png" alt="How Can I Make My App Control Policy Tamper Proof">

<br>

If you cryptographically sign and deploy your App Control policy, it will be tamper-proof and even the system administrator won't be able to remove it without the certificate's private keys 🔑.

<br>

## How Do Enterprises And Businesses Use App Control?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Do%20Enterprises%20And%20Businesses%20Use%20Application%20Control%20(WDAC).png" alt="How Do Enterprises And Businesses Use App Control">

<br>

Businesses and Enterprises have a variety of options. They can set Intune as Managed Installer so any application pushed by the administrator to the endpoints will be trusted and installed but the users won't be able to install new applications on their own.

<br>

## How Many App Control Policies Can Be Deployed On a System?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/How%20Many%20WDAC%20Policies%20Can%20be%20deployed%20on%20a%20sytem.png" alt="How Many WDAC Policies Can Be Deployed On a System">

<br>

There is no limit on how many App Control policies you can deploy on a system.

<br>

## What Is ISG And How Can I Use It In An App Control Policy?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20ISG%20And%20How%20Can%20I%20Use%20It%20In%20An%20Application%20Control%20(WDAC)%20Policy.png" alt="What Is ISG And How Can I Use It In An App Control Policy">

<br>

ISG stands for [The Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph). It's a very powerful AI-based system that processes Trillions of signals from all kinds of data sources every day. You can utilize it as the arbiter in App Control policies so it can help you allow trusted apps and block unknown or malicious apps automatically.

<br>

## What Is Smart App Control?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20Smart%20App%20Control.png" alt="What Is Smart App Control">

<br>

Smart App Control is an automated AI-based Application Control mechanism that uses the same underlying components as App Control for Business. It can be used in all Windows editions and provides great level of security by default for all systems it's enabled on.

<br>

## What Is The Most Secure Level To Use For Authorizing Files?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/What%20Is%20The%20Most%20Secure%20Level%20To%20Use%20For%20Authorizing%20Files.png" alt="What Is The Most Secure Level To Use For Authorizing Files">

<br>

For signed files, you should always use `WHQLFilePublisher` as [main level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) and `FilePublisher` as fallback. For unsigned files, use `Hash` level.

<br>

## Is There A More Automated Way To Use Application Control At Scale?

<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/WDAC%20FAQ/Is%20There%20A%20More%20Automated%20Way%20To%20Use%20Application%20Control%20At%20Scale.png" alt="Is There A More Automated Way To Use Application Control At Scale">

<br>

Yes. [Microsoft Defender for Cloud's](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-adaptive-application-controls) adaptive application controls enhance your security with this data-driven, intelligent automated solution that defines allowlists of known-safe applications for your machines. It uses Machine Learning models and is based on the collected telemetry data.

<br>
