# Signed and Verified commits with GitHub desktop

Web commits, the commits you perform using GitHub website, are automatically verified, but the ones you do from GitHub desktop need to be manually signed.

## Signing using GPG key

### Setting up GPG

Download gpg4win from their [official website]( https://www.gpg4win.org/thanks-for-download.html)

([suggested by GitHub too](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits))

Begin the installation, choose to only install **GnuPG** and **Kleopatra**, don't need any other component.

![image](https://user-images.githubusercontent.com/118815227/233185971-c9a317b7-d2ea-40f6-8415-1b330102831a.png)

After installation, open Kleopatra and create a new GPG key pair by selecting "New Key Pair"

![image](https://user-images.githubusercontent.com/118815227/233190420-c3583888-c3e5-4684-9422-21025ac055da.png)

Enter your real name and the email address that is added as one of your verified email addresses [in your GitHub account settings.](https://github.com/settings/emails)

Select advanced settings and here you can optionally check the box next to "Authentication" and also increase the validity period of your GPG key.

![image](https://user-images.githubusercontent.com/118815227/233327630-abd39242-aeb1-4f95-8247-fbada30995b7.png)

> Choosing a passphrase is not mandatory.

Export the public key by right-clicking on the GPG key and selecting **Export**. Open the exported file in Notepad or VS code, copy its content and paste it in [your GitHub profile's GPG key section](https://github.com/settings/gpg/new) so it can be added as a new GPG key to your GitHub account.

### Configuring .gitconfig file

Assuming GitHub desktop is installed and logged in on your system, open the `.gitconfig` file, usually located in User's folder, and add the following items to it.

Add this section to the end of the file

```
[commit]
  gpgsign = true
```

And then add this to the `[user]` section

```
signingkey = YourGPGSigningkeyID
```

Replace `YourGPGSigningkeyID` with your actual GPG key ID. You can get it from Kleopatra GUI in Key-ID column (enter them without spaces in the `.gitconfig` file) or you can get it from your GPG keys section in [GitHub account settings](https://github.com/settings/keys), Key ID will be visible for you after adding your GPG public key.

You can set the validity period of your GPG certificate to unlimited, set/change/remove its passphrase and other modifications. You can publish it on the GPG server too so others can look it up and verify it.

Make sure you backup your secret key using Kleopatra and store it in a safe place, you can import it again on another machine to continue signing your GitHub commits. Public key doesn't need to be backed up as you can regenerate it again by importing the secret GPG key on a different machine.

Now every time you commit using GitHub desktop, your commits will be signed. If your GPG key has a passphrase, you will be asked to enter it before committing and pushing in GitHub desktop, otherwise signing will happen automatically. Your repository commit history on GitHub website will show verified badge next to them.

<br>

### How to restore GPG for commit signing using your current key on a new environment

1. Install GitHub desktop and log in with your GitHub account
2. Configure the .gitconfig file as explained above
3. install **gpg4win** as explained above
4. Open Kleopatra GUI and use the Import button to import your GPG secret key backup to the program. You can also double-click on your GPG secret key backup file and add it to the program that way.
5. Start committing and pushing changes to your repository using GitHub desktop app, your commits will have a verified badge on GitHub website commit history.

<br>

### Official resources

[Telling Git about your signing key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key#telling-git-about-your-gpg-key-1)

<br>

***

<br>

## Signing using SSH key

### Generating the key pair

Run this command to create a new SSH key pair, using the provided email as a label. It should be one of the emails added to your account as a verified emails.

```powershell
ssh-keygen -t ed25519 -C "spynetgirl@outlook.com"
```

> Replace spynetgirl@outlook.com with your own email address

When asked, enter a file name, don't need to specify a file extension (such as .txt). 2 files will be created in User folder. The one with `.pub` extension contains your public key, the other one contains your private keys. Both of them must be backed up and stored in a safe place.

Set a passphrase when asked, not mandatory so you can just press enter when asked for a passphrase.

<br>

### Configuring SSH Windows service

```powershell
Set-Service -Name ssh-agent -StartupType Automatic
Set-Service -Name ssh-agent -Status Running
```

First make sure you've moved the generated SSH key pair from the default User folder location and stored them somewhere else, can be OneDrive's personal vault, and then run the following command to add the private key of your SSH key pair to the SSH agent.

```powershell
ssh-add "Path/To/SSH/Privatekey"
```

If you set a passphrase for your private key from previous steps then you'll be asked to enter it, otherwise you will see the successful message saying "Identity added".

<br>

### Add your SSH public key to GitHub account

Open the file containing your SSH public key, which has a `.pub` extension, using a text editor such as Notepad or VS code, copy its content and paste it in [your GitHub account settings](https://github.com/settings/ssh/new) and save.

<br>

### Configuring .gitconfig file

Add these new sections to the end of your `.gitconfig` file. It's usually located in User folder `C:\Users\YourUserName`

```
[gpg]
    format = ssh
[commit]
    gpgsign = true
```

and add this to the `[user]` section to define your SSH public key, it's a direct path to that file.

```
signingkey = "Path/To/SSH/SSHKey.pub"
```

**You must replace all of the backslashes `\` with forward slashes `/` in your path, otherwise GitHub desktop throws an error.**

Now every time you commit using GitHub desktop, your commits will be signed. If your SSH key has a passphrase, you will be asked to enter it before committing and pushing in GitHub desktop, otherwise signing will happen automatically. Your repository commit history on GitHub website will show verified badge next to them.

<br>

### How to restore SSH for commit signing using your current key on a new environment

1. Install GitHub desktop and log in with your GitHub account
2. Configure the .gitconfig file as explained above
3. Turn on the `ssh-agent` Windows service
4. Add your SSH private key to `ssh-agent` using `ssh-add "Path/To/SSH/Privatekey"` command
5. Start committing and pushing changes to your repository, your commits will have a verified badge on GitHub website commit history.

<br>

### Official resources

[Telling Git about your SSH key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key#telling-git-about-your-ssh-key)

[Key-based authentication in OpenSSH for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)

[About commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification)

[Adding a new SSH key to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)

[Generating a new SSH key and adding it to the ssh-agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent)

<br>
