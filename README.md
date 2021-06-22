# TrustedInstallerToken

I couldn't find any examples of programatically acquiring a TrustedInstaller token without stealing one from an already running process, so I decided to quickly draft up a POC.

The TrustedInstaller token is created through a call to `LogonUserExExW`, adding the TrustedInstaller SID to the groups of the new token.

This method requires the running process to hold the `SeTcbPrivilege` privilege. If `SeTcbPrivilege` is not held but `SeDebugPrivilege` is held the process will acquire the tcb privilege by impersonating a token from `winlogon.exe`

It is also possible to create a TrustedInstaller token using `NtCreateToken` if `SeCreateTokenPrivilege` is held (the privilege could also acquired from `lsass.exe`), but since there are existing examples of `NtCreateToken` on github I did not bother including it in this project.


