# Cryptographic Bill of Materials

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/35b963aab5530fd6b084f2e37cc25860bc999747/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/Cryptographic%20Bill%20of%20Materials.png" alt="CBOM in Harden System Security">

</div>

<br>

The Cryptographic Bill of Materials (CBOM) offers a system-level inventory and introspection of the operating system cryptography, surfacing the algorithms, curves, cipher suites, and providers that define the platform's cryptographic posture. By normalizing what the OS exposes, it delivers SBOM-like transparency for crypto: enabling evidence-based audits, baseline conformance checks, drift detection across updates, identification of legacy/weak primitives, and planning for [post-quantum](https://techcommunity.microsoft.com/blog/microsoft-security-blog/post-quantum-cryptography-comes-to-windows-insiders-and-linux/4413803) transitions. Enumerations are sourced directly from the underlying providers to emphasize fidelity and provenance, making the output suitable for compliance artifacts, interoperability analysis, and informed hardening and policy decisions as standards evolve.

## What the Page Provides

The CBOM page gathers and presents cryptographic capabilities directly from the operating system, organized into five views:

- Crypto Algorithms
  - All OS-registered cryptographic algorithms across operation classes (cipher, hash, signature, RNG, key derivation, asymmetric, secret agreement).
  - Availability checks indicating whether an algorithm can be opened by the platform at runtime.
  - Post‑quantum awareness: heuristic detection of PQ families (ML‑KEM/Kyber, ML‑DSA/Dilithium, SLH‑DSA/SPHINCS+, and well-known candidates).
  - Capability probing for PQ algorithms: key generation support and parameter sets that successfully apply and finalize.

- CNG Curves
  - ECDH curves exposed via CNG.
  - For each curve: canonical name, OID (when resolvable), and public key length (bits).

- SSL Provider Curves
  - ECC curves visible through the SSL/TLS provider layer.
  - For each curve: provider-reported name, OID, public key length (bits), curve type, and flags.

- TLS Cipher Suites
  - TLS/DTLS cipher suites resolved from the platform's SSL context.
  - For each suite: supported protocol versions, cipher and hash selections, certificate type, key exchange metadata, numeric suite identifiers (including hex forms), and key-related lengths.
  - A `Configured only` toggle to focus the list on suites currently configured/enabled by the system vs. the broader set known to the provider(s).

- Registered Providers
  - The set of cryptographic providers registered with the platform.

All data is gathered from the system's low level cryptographic subsystems to reflect the effective state of the host where the app runs.

## How to Use the Page

- Retrieval
  - Each tab includes a Retrieve button to query the OS and refresh the view.

- Search and filter
  - Each tab provides a search box that filters the current view in real time (case‑insensitive).

- Sort
  - Click any column header to sort ascending/descending by that field; sorting persists within the session.

- Copy to clipboard
  - Right‑click or tap and hold on any row to copy the entire row or an individual field for easy sharing or documentation.

- Export CBOM
  - Use the `Generate CBOM` button in the tab strip to export a JSON file representing the full inventory, including host metadata and tool version.

## Data Sources and Fidelity

CBOM prioritizes fidelity by reading from the OS cryptographic layers:

- Algorithms are enumerated from the platform's registered operation classes. Availability is verified by attempting to open an algorithm provider.
- Post‑quantum detection is based on standardized naming and common vendor conventions. Where possible, the app attempts non‑destructive key‑pair generation and parameter‑set assignment prior to finalization to confirm practical support.
- CNG (ECDH) curve names are enumerated from the system's curve list, with key length derived from key length metadata or ECC parameter field length. OIDs are resolved when the platform can map a curve name to an OID.
- SSL/TLS cipher suites and ECC curves are resolved through the platform SSL context and provider interfaces to reflect what the OS stack reports, including protocol affinities.
- Registered providers are listed from the platform registry of cryptography providers.

Because the app reflects the live host state, results naturally incorporate vendor updates, policy changes (e.g., FIPS mode), and OS servicing.

## Post‑Quantum Awareness

Where PQ algorithms are exposed by the platform:

- Detection: Names matching standardized families (e.g., ML‑KEM/Kyber, ML‑DSA/Dilithium, SLH‑DSA/SPHINCS+) are flagged as post‑quantum.
- Capability probing: The app attempts to generate and finalize a key pair and, for known families, apply candidate parameter sets (e.g., MLKEM512/768/1024, MLDSA44/65/87, SLHDSA variants) before finalization. Parameter sets that successfully apply and finalize are reported as supported.

Note: Detection is name‑based and thus subject to provider naming; capability probing confirms support where the platform permits.

## Exported CBOM Format

The exported JSON is a single document meant for audit and archival workflows:

- Metadata includes:
  - Timestamp (UTC), host machine name, OS description, architecture, FIPS policy state.
  - Tool identity and version.
- Content includes:
  - Algorithms
  - CNG Curves
  - SSL Provider Curves
  - TLS Cipher Suites
  - Registered Providers

A minimal, illustrative shape (truncated for clarity):

```json
{
  "BomFormat": "CBOM",
  "SpecVersion": "1.0",
  "Metadata": {
    "Timestamp": "2025-04-10T05:57:45Z",
    "Host": {
      "Machine": "Mainframe-30541",
      "OsVersion": "Microsoft Windows 10.0.26220",
      "Architecture": "ARM64",
      "IsFIPSPolicyEnabled": false
    },
    "Tool": {
      "Name": "Harden System Security Application",
      "Website": "https://github.com/HotCakeX/Harden-Windows-Security",
      "Version": "1.0.15.0 - Internal"
    }
  },
  "Algorithms": [
    {
      "Name": "AES",
      "OperationClass": 1,
      "Flags": 0,
      "AlgorithmType": "Cipher",
      "IsOpenable": true,
      "IsPostQuantum": false,
      "SupportsKeyGeneration": false,
      "SupportedParameterSets": []
    }
    // ...
  ],
  "CngCurves": [
    {
      "Name": "brainpoolP160r1",
      "Oid": "1.3.36.3.3.2.8.1.1.1",
      "PublicKeyLengthBits": 160
    }
    // ...
  ],
  "SslProviderCurves": [
    {
      "Name": "curve25519",
      "Oid": "",
      "PublicKeyLengthBits": 255,
      "CurveType": 29,
      "Flags": 10
    }
    // ...
  ],
  "TlsCipherSuites": [
    {
      "Name": "TLS_CHACHA20_POLY1305_SHA256",
      "Protocols": [
        772
      ],
      "ProtocolNames": [
        "TLS 1.3"
      ],
      "Cipher": "CHACHA20_POLY1305",
      "CipherSuite": 4867,
      "CipherSuiteHex": "0x1303",
      "BaseCipherSuite": 4867,
      "BaseCipherSuiteHex": "0x1303",
      "CipherLength": 256,
      "CipherBlockLength": 1,
      "Hash": "",
      "HashLength": 0,
      "Exchange": "",
      "MinimumExchangeLength": 0,
      "MaximumExchangeLength": 0,
      "Certificate": "",
      "KeyType": 0
    },
    // ...
  ],
  "RegisteredProviders": [
    "Microsoft Key Protection Provider",
    "Microsoft Passport Key Storage Provider",
    // ...
  ]
}
```

## Security and Privacy

- The exported filename includes the machine name by default. You may rename the file before sharing.
- Host metadata (machine name, OS description, architecture, FIPS state) is included to make audits reproducible and results comparable across systems.
- No secrets or private keys are accessed. Capability checks use ephemeral, in‑memory handles and are destroyed immediately after probing.

