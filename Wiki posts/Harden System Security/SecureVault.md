# Secure Vault

Secure Vault is a feature in the Harden System Security app that lets you create portable encrypted vaults anywhere you choose in order to store secrets and safely access them whenever you want. At the moment, it only supports TOTP (Time-based One-Time Password) secrets, but it will be expanded in the near future to support more types of secrets. TOTPs are tokens that you receive from websites or services when you enable two-factor authentication.

## Vault Cryptographic Architecture

Secure Vault uses authenticated encryption, strong password-based key derivation, and a layered key hierarchy to protect vault contents.

The vault uses **AES-256-GCM (Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode)** for encryption and authentication. AES-GCM protects both confidentiality and integrity, which means encrypted vault data cannot be read or modified without detection. The implementation uses a **96-bit AES-GCM nonce** and a **128-bit AES-GCM authentication tag**.

The vault password is not used directly to encrypt TOTP secrets. Instead, the password is processed with **PBKDF2-HMAC-SHA3-512 (Password-Based Key Derivation Function 2 using Hash-based Message Authentication Code with Secure Hash Algorithm 3 with a 512-bit digest)** using **1,000,000 iterations** and a **256-bit random salt**. This produces password-derived key material used to protect the vault's internal key material.

Secure Vault generates a random **256-bit vault data key** for the vault. This vault data key is protected using **AES-256-GCM** with key material derived from the user's password. The encrypted vault data key is stored in the vault file alongside the password KDF (Key Derivation Function) parameters required to unlock it.

Token records are encrypted with a separate record encryption key derived from the vault data key using **HKDF-SHA3-512 (HMAC-based Key Derivation Function using SHA3-512)**. This creates a clear cryptographic hierarchy:

1. The user password derives password-based key material.
2. The password-derived key material unlocks the vault data key.
3. The vault data key derives the record encryption key.
4. The record encryption key protects the encrypted TOTP records.

Each TOTP record is encrypted independently with **AES-256-GCM**. A record contains the token metadata, TOTP algorithm, digit count, period, secret bytes, and notes. Each encrypted record has its own AES-GCM nonce, authentication tag, and ciphertext, so records are protected as separate authenticated payloads inside the same vault.

Secure Vault uses **AAD (Additional Authenticated Data)** with AES-GCM to bind encrypted data to vault-specific metadata. AAD is authenticated but not encrypted. This means vault context can become part of the authentication boundary without becoming part of the ciphertext itself. If that authenticated context changes, AES-GCM verification fails and the encrypted data is rejected.

The AAD is built from structured vault context and hashed with **SHA3-512** before being supplied to AES-GCM. Separate AAD domains are used for vault key wrapping and token record encryption, keeping each cryptographic operation scoped to its intended purpose and preventing encrypted components from being replayed or interpreted in the wrong cryptographic context.

The vault is stored as a JSON envelope and uses the following cryptographic parameters:

| Component | Algorithm or value |
| --- | --- |
| Vault encryption | **AES-256-GCM** |
| Password key derivation | **PBKDF2-HMAC-SHA3-512** |
| Password KDF iterations | **1,000,000** |
| Password KDF salt size | **256-bit** |
| Vault data key size | **256-bit** |
| Record key derivation | **HKDF-SHA3-512** |
| AES-GCM AAD hashing | **SHA3-512** |
| AES-GCM nonce size | **96-bit** |
| AES-GCM authentication tag size | **128-bit** |
| Vault format version | **1** |

For TOTP generation, Secure Vault supports the standard HMAC-based algorithms:

| TOTP algorithm | Hash function |
| --- | --- |
| SHA1 (Secure Hash Algorithm 1) | **HMAC-SHA1** |
| SHA256 (Secure Hash Algorithm 2 with a 256-bit digest) | **HMAC-SHA256** |
| SHA512 (Secure Hash Algorithm 2 with a 512-bit digest) | **HMAC-SHA512** |

Supported TOTP code lengths are **6**, **7**, and **8** digits. The default manual-entry profile is **HMAC-SHA1**, **6 digits**, and a **30-second** period.

## Runtime Memory Protection

Secure Vault does not leave its most sensitive runtime material exposed in ordinary plaintext memory while the vault is unlocked. After the vault is opened, the vault data key and stored TOTP secret material are placed under an additional in-memory protection layer using Windows protected memory.

This protection uses **CryptProtectMemory** with **CRYPTPROTECTMEMORY_SAME_PROCESS** scope. In this mode, protected memory is encrypted so that it can only be decrypted by the same process that protected it. The protected memory is not designed for long-term storage and is not a replacement for the vault's file encryption. It is a runtime hardening layer for sensitive data that must temporarily exist while the app is active.

The vault data key is protected in memory after the vault is unlocked. When Secure Vault needs to load records, save records, derive record keys, or perform a vault operation that requires the data key, the key is briefly unprotected, used for the required cryptographic operation, and then protected again. This keeps the vault's root runtime secret sealed by default instead of leaving it constantly exposed for the full unlocked session.

Each TOTP secret is also held in protected memory while the vault is unlocked. The secret is unprotected only at the moment Secure Vault needs to generate a code, compare secrets, copy secret bytes for an internal operation, or export decrypted data after explicit confirmation. As soon as the operation completes, the secret is protected again.

This creates a tactical runtime posture:

1. The encrypted vault file protects secrets at rest.
2. The vault data key unlocks the encrypted vault records only after the correct password is supplied.
3. The vault data key is then protected in memory while the vault remains unlocked.
4. Each TOTP secret is also protected in memory between active use windows.
5. Sensitive buffers are cleared when tokens are removed, the vault is locked, the page unloads, or temporary cryptographic material is no longer needed.

Runtime memory protection is a defensive hardening layer, not a claim of absolute memory invisibility. Any secret that must be used by software must exist in plaintext briefly at the point of use. Secure Vault's strategy is to keep those windows narrow, controlled, and purpose-bound: unseal only when needed, execute the mission, reseal immediately, and burn temporary material after contact.

## Creating a New Vault

When no vault exists yet, Secure Vault opens in the **Create or import a vault** state. The main vault workspace remains visually locked, and the creation card becomes the primary interaction surface. This keeps the user focused on establishing the vault boundary before any secrets can be added or viewed.

The create flow presents two password controls:

1. **New vault password**
2. **Confirm new vault password**

Both fields are required. The vault is created only when the two password values match exactly and the password satisfies the required strength rules.

A password strength indicator is shown above the password fields. It gives immediate feedback while the user types, helping them understand whether the password is ready to protect the vault. The password must include:

- At least **6 characters**
- At least **one lowercase letter**
- At least **one uppercase letter**
- At least **one number**

Spaces and symbols are treated as strength bonuses. They are not required, but they improve the displayed strength score.

> [!IMPORTANT]
> Even though the minimum required password length is `6`, it is strongly recommended to use a longer password for better security. A longer password increases the time and effort required for brute-force attacks.

### Importing an Existing Vault

The create card also includes an **Import vault** action. This gives users a direct recovery path when they already have an existing encrypted vault file. You can import a vault from any location on your device. The imported vault must be in the correct JSON format and must've been previously created by the Harden System Security app. After selecting the vault file, you will be prompted to enter the vault password to unlock it.

> [!TIP]
> Secure Vault can also be used with cloud synchronization by placing the vault file inside a OneDrive-backed folder. Once the vault location is changed to OneDrive, Harden System Security saves all vault updates directly to that location, allowing OneDrive to synchronize the encrypted vault file across your devices.

## User Interface Controls and Navigation

After a vault is created or unlocked, Secure Vault transitions into the main vault workspace. Token creation is available through two primary entry modes:

1. **Paste mode** lets the user add one or more `otpauth://totp/` entries directly from authenticator setup links.
2. **Manual mode** lets the user create a token by entering the secret and related account details manually.

A search box allows tokens to be filtered quickly by their visible name or notes. This keeps large vaults usable without forcing the user to visually scan every stored entry.

Each token appears as an individual card. A token card presents the current code, the remaining time before rotation, and the core actions for that token. The user can copy the active code, manage notes, or remove the token from the vault.

Notes provide an optional place to store context for a token, such as account purpose, recovery hints, or environment details. Notes can be added, edited, previewed, or cleared from the token card controls.

Vault-level actions are grouped separately from token-level actions. These controls include locking the vault, changing the vault password, changing the vault location, enabling or disabling auto-lock, clearing all tokens, and exporting decrypted vault contents when explicitly requested.

> [!IMPORTANT]
> Destructive and sensitive actions are intentionally gated. Operations such as deleting the vault, clearing all tokens, removing a token, or exporting decrypted data require a hold-to-confirm interaction. This prevents accidental activation and makes high-impact actions deliberate.

<br>

<div align="center">

<img src="https://github.com/HotCakeX/.github/blob/main/Pictures/Gifs/HardenSystemSecurity-SecureVault-ConfirmationAnimatedButton.gif?raw=true" alt="Harden System Security Secure Vault Confirmation Behavior"/>

</div>

<br>

Auto-lock provides an additional safety layer by returning the vault to the locked state after inactivity. When the vault locks, the workspace becomes inaccessible until the correct vault password is entered again.

Together, these controls keep the interface direct and operationally focused: unlock the vault, find the token, use the code, manage secrets when needed, and lock the vault when finished.

### Side-Channel Isolation Mitigations

You can enable side-channel isolation mitigations in the Secure Vault page by toggling its option. The mitigations are only applied early during app startup sequence so in order for your changes to take effect, you need to restart the app after enabling/disabling that option.

They control mitigation behaviors related to side-channel attack surfaces, including speculative execution behavior and page combining.

| Mitigation | Technical behavior |
| --- | --- |
| SMT branch target isolation | Requests hardware mitigations that prevent cross-SMT-thread branch target pollution while the process is executing in user mode. If the hardware does not support the mitigation, or if the mitigation is disabled system-wide, this setting has no effect. |
| Isolate security domain | Isolates the process into a distinct security domain, even from other processes running under the same security context. This prevents cross-process branch target injection. It also limits page combining to processes within the same security domain, effectively restricting combining to the process itself except for common pages, unless page combining is further restricted. |
| Disable page combine | Disables page combining for the process, including internal page combining within the process itself, except for common pages such as pages made entirely of zeroes or entirely of ones. |
| Speculative store bypass disable | Requests hardware mitigation for Speculative Store Bypass while the process is executing in user mode. This is used to mitigate intra-process Speculative Store Bypass exposure. If the hardware does not support the mitigation, or if the mitigation is disabled system-wide, this setting has no effect. |
| Restrict core sharing | Requests scheduler isolation so threads in the process are not scheduled on the same physical core as threads from another security domain. This policy cannot be enabled on systems where the scheduler cannot provide that guarantee, such as certain virtual machine environments unless the hypervisor reports the absence of non-architectural core sharing. |

These options are designed for high-isolation workloads where the process should reduce exposure to cross-thread, cross-process, or cross-security-domain side-channel vectors. Keep in mind that enabling these mitigations may have performance implications, so they should be used based on the specific security requirements of your environment.
