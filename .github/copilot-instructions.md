pinpam is a collection of tools and pam modules for tpm-based authentication.

It includes a core library for TPM authentication, implementing PIN-based auth and a master key system for consistent user tokens, allowing for any PAM auth method to be used while still having a stable token for unlocking keyrings/disks/etc. Both of these pam modules can be used independently or together, and the master key system can be used with any PAM auth method.

A pinutil CLI tool is included for managing tpm based pins and the master key.

Locale support must be included for any user-facing messages.

It is important that users cannot access the TPM without going through the pinpam modules, as they enforce important security properties. pinutil is configured as a setgid binary in a dedicated tss group to allow non-root users to perform necessary TPM operations without granting them full root access. The PAM modules call this binary so they can escalate to that group's privileges for TPM operations without granting them full root access.

Security controls in place include:
- Real UID == 0 required for pinutil master-key / pin reset operations.
- PolicyWrite restrictions barring even root from resetting PIN failure counts without erasing the pin entirely.
- Landlock LSM policies restricting ambient rights to the minimum necessary.

This project is built as a nixos flake, which handles the onerous pam configuration and groups for the user automatically. There is also an AUR package, but this requires more manual setup.

Priorities:
1. Backward compatibility: No existing auth methods / tpm tokens should be invalidated, and migrations should be in place if breaking changes are necessary, by using versions. Don't bump / create migrations if the change is non-breaking.
2. Security: There is limited protection we can do against a privileged attacker, but we should make sure to follow best practices and not make things worse.
3. Independence from system specific features: Hard systemd dependency, hardcoded paths, etc should always be avoided. This project should work on any modern Linux distro with a reasonably recent kernel and TPM 2.0 support, without requiring specific init systems or other system features. This is both for user flexibility and to avoid issues with distro-specific features / configs. We can assume we are running linux on a random obscure distro, with tpm, nothing else is guaranteed.

Instructions:
1. When a feature breaks / troubleshooting is being conducted, the answer is not "remove it" or disable xyz if abc is the issue. Fix underlying issues, and if you can't, try harder. TPM is poorly documented and quirky, so trial and error is expected, but we should be trying to find solutions, not just workarounds.
2. If during the troubleshooting process, you find that something you changed to get it to work, the previous things you tried that didn't work can be removed. Don't leave in a bunch of commented out code or "attempted" things that didn't work, as it clutters the codebase and makes it harder to understand.
3. Less is more. An elegant clean solution with fewer lines of code means less things to break.

Coding style: Boring, conservative, consistent, DRY.