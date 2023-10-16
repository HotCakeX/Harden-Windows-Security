# Cloning Personal and Enterprise Repositories Using GitHub Desktop

[GitHub Desktop](https://desktop.github.com/) enables you to effortlessly clone and manage repositories using a user-friendly graphical interface. GitHub offers various types of repositories, such as personal, [Enterprise Cloud](https://docs.github.com/en/get-started/onboarding/getting-started-with-github-enterprise-cloud) and [Enterprise Server (Self-Hosted)](https://docs.github.com/en/enterprise-server@3.9/admin/overview/about-github-enterprise-server). All of them can either be configured as public or private.

[Cloning](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) a GitHub Enterprise Cloud repository differs from cloning a personal repository. GitHub personal repositories necessitate you to provide the clone URL or simply authenticate with your personal GitHub account credentials.

GitHub Enterprise Cloud repositories, however, require SSO (Single Sign-On) claim to be added to GitHub Desktop before you can access those repositories. GitHub Desktop runs a loopback token collection server when you sign in.

If you attempt to sign in without SSO claim, it will be absent from the GitHub Desktop app and you will not be able to clone GitHub Enterprise Cloud repositories.

At this point, you have to:

1. Sign out of GitHub Desktop
2. Go to [GitHub.com](https://github.com)
3. Use the "Single Sign-on" link at the top to sign in to your Enterprise Cloud
4. Now go back again to GitHub Desktop -> Options
5. Use the Sign in button; The browser will be opened and this time when you sign in to GitHub Desktop, the SSO claim to your existing account that grants you access to Enterprise Cloud repositories will be appended as well.

<br>
