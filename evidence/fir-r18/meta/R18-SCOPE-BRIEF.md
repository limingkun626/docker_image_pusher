# R18 Scope Brief

Authorized outcome: remove macOS from the product support scope and remove every
macOS support declaration, code path, test requirement, release gate, and future
verification requirement. Preserve Windows 10/11 and WSL Linux support.

Fixed decisions:

- R13 through R17 evidence remains immutable.
- Supported platforms are Windows 10/11 and WSL Linux.
- macOS and native non-WSL POSIX are explicitly unsupported.
- Release verification requires Windows and Linux only.
- macOS-specific tests, workflow runners, artifact provenance, and matrix
  requirements must be deleted from the R18 product and release tooling.
- Third-party dependency file names such as `platformdirs/macos.py` are closure
  bytes, not product support declarations, and must not be confused with scope.
- The new candidate version is `1.4.3`.
