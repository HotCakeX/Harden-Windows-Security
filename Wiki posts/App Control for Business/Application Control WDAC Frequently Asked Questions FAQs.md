# Application Control (WDAC) Frequently Asked Questions (FAQs)

## What's The Difference Between Application Control Policies And An Antivirus?

Application Control policies are based on whitelisting strategy, meaning everything is blocked by default unless explicitly allowed. Antiviruses on the other hand are based on blacklisting strategy, meaning everything is allowed by default unless explicitly blocked.

## How Does App Control In The OS Compare To 3rd Party Solutions?

App Control which is built deep inside of the OS kernel doesn’t need any “agents” to be installed, that means it can’t be killed using techniques used against 3rd party solutions, it also doesn’t increase the attack surface of the system. It’s native and exceedingly fast which makes it transparent to the user.

## Can I Use Microsoft Defender For Endpoint (MDE) To Collect App Control Logs?

Yes. [MDE Should definitely be used](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Use-Microsoft-Defender-for-Endpoint-Advanced-Hunting-With-WDAC-App-Control) to manage your endpoints and collect Code Integrity logs used to create App Control policies. They provide very detailed CI info at scale for your entire fleet of machines. Then Intune can be used for at scale deployment of the policies after creation.

## Can Supplemental Policies Have Deny Rules?

No, Supplemental policies are only used to expand a base policy by allowing more files.

## How Can I Make My App Control Policy Tamper Proof?

If you cryptographically sign and deploy your App Control policy, it will be tamper-proof and even the system administrator won't be able to remove it without the certificate's private keys 🔑.

## How Do Enterprises And Businesses Use App Control?

Businesses and Enterprises have a variety of options. They can set Intune as Managed Installer so any application pushed by the administrator to the endpoints will be trusted and installed but the users won't be able to install new applications on their own.

## How Many App Control Policies Can Be Deployed On a System?

There is no limit on how many App Control policies you can deploy on a system.

## What Is ISG And How Can I Use It In An App Control Policy?

ISG stands for [The Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph). It's a very powerful AI-based system that processes Trillions of signals from all kinds of data sources every day. You can utilize it as the arbiter in App Control policies so it can help you allow trusted apps and block unknown or malicious apps automatically.

## What Is Smart App Control?

Smart App Control is an automated AI-based Application Control mechanism that uses the same underlying components as App Control for Business. It can be used in all Windows editions and provides great level of security by default for all systems it's enabled on.

## What Is The Most Secure Level To Use For Authorizing Files?

For signed files, you should always use `WHQLFilePublisher` as [main level](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) and `FilePublisher` as fallback. For unsigned files, use `Hash` level.

## Is There A More Automated Way To Use Application Control At Scale?

Yes. [Microsoft Defender for Cloud's](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-adaptive-application-controls) adaptive application controls enhance your security with this data-driven, intelligent automated solution that defines allowlists of known-safe applications for your machines. It uses Machine Learning models and is based on the collected telemetry data.
