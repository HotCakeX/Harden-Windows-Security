# About TLS, DNS, Encryption and OPSEC concepts

<p align=center>
<img width=500 src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/6.jpg" alt="About TLS, DNS, Encryption and OPSEC concepts">
</p>

The contents here are for beginners, to learn the basics of TLS, encrypted connections and some preliminary OPSEC (Operational security) concepts.

<br>

## DNS

Let's talk about DNS first.
Whether you are using Secure DNS such as DNS over HTTPS or using plain text DNS (Default port: 53), the domain name is the only piece of information that the DNS server provider will see. DNS does not deal with URLs, only domain names.

E.g., in this URL, anything after the first `/` is inaccessible to the DNS server.

```
Github.com/HotCakeX/Harden-Windows-Security
```

The DNS provider will know that you are accessing GitHub.com but won't know which repository on GitHub.com you are visiting.

* DNS doesn't resolve URLs, only enables the DNS client to find the IP Address of the server part of the URL, the rest is handled by HTTP protocol/request. The part before the slash is the DNS-provided hostname or an ordinary IP address. The part after the slash indicates the application on that host. DNS does not deal with anything after the slash at all.

* Anything in the URL that is not domain name is encrypted as part of the HTTP request, which uses TLS for encryption and that's why it's HTTPS. They are invisible to the DNS server and anyone else other than the webserver hosting the website you are visiting.

* [Extra info](https://superuser.com/a/927891)

* [Extra info](https://serverfault.com/questions/173187/what-does-a-dns-request-look-like/173193)

<br>

## About DNS Leak in plain text DNS

When you are using VPN or proxies, it's important to make sure there is no DNS leakage. Properly implemented and configured VPNs/Proxies don't have this problem.

The most practical way to see if you have DNS leak while using a VPN/Proxy is to use Wireshark to monitor your outbound connections on the edge of your network. Simply type `dns` in the Wireshark's display filter bar and observe the results. If you are using a proper VPN/Proxy or if you are using Secure DNS such as DoH or DoT, then you shouldn't see any results because that keyword only displays plain text DNS over the default port 53.

<br>

## DNS Security

DNSSEC by itself without using DoH/DoT [can be downgraded](https://arxiv.org/abs/2205.10608). If you're using DoH or DoT you must be safe as long as you are using a trusted DNS provider and your certificate authority storage is not poisoned/compromised.

<br>

## Certificates and TLS

Certain countries with dictatorship or theocracy governments make people install their own root certificate to perform TLS-termination and view their data in plain-text even when HTTPS is being used. One example is what happened in Kazakhstan.

Certain applications install root certificates, such as 3rd party antiviruses. They are all equally dangerous and must be avoided.

<br>

## DNS Privacy

Using **DNS-over-TLS** or **DNS-over-HTTPS** mitigates some privacy leaks, because now the ISP won't have the domain you are visiting, but only the IP address. It's possible that more than one site uses the same IP address, so in some cases, it's not possible to say for sure that you are visiting SiteA.com when SiteB.com shares the same IP (Unless you are using TLS v1.2 which leaks Certificate's common name, more on that later), and high-traffic sites usually employ a CDN (content delivery network) to distribute traffic, and the IP they use are not the site's IP, but an IP belonging to the CDN (like CloudFlare or Akamai).

Website owners use CDNs like Cloudflare for two purposes:

1. Best user response time by using the nearest server.

2. Load-balancing in case of the nearest server being overloaded (DDoS and more) and then pointing to the next-nearest server.

Browsers such as Microsoft Edge only support DNS over HTTPS.
Windows supports DNS over HTTPS and DNS over TLS.

DNS over HTTPS is preferred because by default it uses the same port 443 as the rest of the HTTPS traffic on the Internet, that makes it harder to be detected and blocked. DNS over TLS on the other hand uses TCP port 853 by default and a filter on that port would block DNS over TLS entirely, whereas blocking port 443 is impractical as it essentially cripples the entire Internet.

<br>

## DNS Caching

DNS caches, just like DNS itself, only map domain names to values ('A' records), never the other way around.

Both the DNS cache, and the DNS system as a whole, only care that bing.com points to 1.2.3.4, not that the address "points" back.

Entries in the DNS cache look exactly like entries in authoritative DNS servers, with domain name as the lookup key.

<br>

## TLS Security in Windows

Windows components (Tested on Windows 11 22H2) rely on TLS 1.2, and that makes them dependent on ECC Curves. So, when enforcing TLS 1.3 only for Schannel, Windows components stop working.

TLS 1.3 cipher suites don't require ECC curves.

NistP256 ECC curve is a must have, otherwise Windows update won't work.

nistP521 is the best ECC curve in terms of security, but curve25519 is also the best non-Nist one, which is also secure and popular.

<br>

## Certificates

Handshake messages contain the certificates (both from server and client), and they are encrypted in TLS 1.3, which means that you cannot see these without breaking the encryption.

<br>

## SNI

SNI, which is part of the handshake, is still unencrypted even in TLS v1.3. The only way to encrypt SNI is to use ECH (Encrypted Client Hello).

<br>

## OPSEC

Assuming you are operating in a hostile country (E.g, China, Russia, Iran), you must be aware of the following information to keep your digital footprint minimal.

There are 4 pieces of information that can reveal which websites/apps/services you use, to the ISP/government.

### DNS

Avoid using plain text DNS as much as you can. Use DNS over HTTPS for security and anonymity. Governments can block well-known servers quickly, you can however self-host on a private cloud or use a serverless DNS to have access to a new endpoint for DoH over a newly setup domain.

If plain text DNS over port 53 is used, and you are not using a proper VPN like OpenVPN or WireGuard, or you are using proxy, then eavesdropper can see the website domain/sub-domain you are visiting. If you use secure DNS like DNS over HTTPS, then DNS becomes fully encrypted and all they can see is the domain name of the Secure DNS server as well as the IP addresses of the websites you connect to.

### Certificate (common name etc.)

**Use TLS v1.3.** When using TLS v1.3, the certificate part of the HTTPS connection is encrypted and none of its details are visible to the eavesdropper. TLS v1.2 handshakes do not encrypt the certificates, resulting in the common name and the website you are visiting to be revealed to the eavesdropper.

[Read more](https://superuser.com/questions/1648334/in-wireshark-where-can-i-find-the-tls-servers-certificate)

### URL

The full path to a web page or web resource is sent over HTTP protocol, so if website uses HTTPS, it's all encrypted.

When using HTTPS, the path and query string (everything after TLD and slash /) is encrypted and not available to anybody but the client and server, the answer is encrypted as well.

### SNI (Server Name Indication or Client Hello)

**This is the most important part**. Even after using:

1. HTTPS to encrypt the full URL path

2. DoH to encrypt the DNS

3. TLS v1.3 to encrypt the certificate

If you don't use a proper VPN, SNI can still reveal the domain and sub-domain of the website you are visiting to the eavesdropper. To secure that, the browser and the website must support ECH (Encrypted Client Hello) or use proper VPN like OpenVPN or WireGuard.

<br>

![About TLS, DNS, Encryption and OPSEC concepts](https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/About%20TLS%2C%20DNS%2C%20Encryption%20and%20OPSEC%20concepts.png)

<br>

## Wireshark

Interesting and useful columns to add to the Wireshark GUI for better visibility into your network connections:

* Use `tls.handshake.type == 11` to filter certificates, only works for TLS v1.2 and below since they don't encrypt that part of the handshake.

* Use `ssl.handshake.extension.type == "server_name"` to filter SNI or Server Name Indication. [More info](https://superuser.com/questions/538130/filter-in-wireshark-for-tlss-server-name-indication-field) (When using VPN, you either shouldn't be seeing any SNI at all or only see the SNI that belongs to the VPN server's domain.)

* Cipher Suites is also an interesting column to add to your Wireshark profile.
