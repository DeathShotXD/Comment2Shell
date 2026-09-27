# Changelog

Notable changes to Comment2Shell, newest first. The format follows Keep a
Changelog and the project uses semantic versioning.

## Unreleased

### Fixed

- The remote IOC check treated a plugin directory listing that returned
  403 as a finding and always exited 0. It now reports the disabled
  listing as a note, probes the six character plugin directories the tool
  itself creates, and exits non-zero when it finds indicators.
- Removed five unused imports.

### Added

- SECURITY.md with the disclosure process and scope.

## 1.0.0 - 2026-09-23

### Added

- Passive version scan, active XSS probe, and the full pre-authentication
  to RCE exploit chain.
- Interactive shell and single command execution against a planted shell.
- Automatic shell cleanup after the command runs.
- Server-side and network IOC checks, and a nuclei detection template.
- Docker lab for WordPress 7.1.0 with setup and cleanup scripts.
