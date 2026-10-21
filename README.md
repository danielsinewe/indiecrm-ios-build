# IndieCRM private iPhone build transport

This repository contains build infrastructure only. Owner-dispatched builds
validate the pinned IndieCRM source on a standard macOS runner. Application
source arrives as an authenticated AES-256-GCM envelope. Diagnostics and unsigned
archives are encrypted to a separate RSA recipient before upload. Plaintext
source, logs, signing credentials and archives are never published here.

Requests are bound to the full source commit. The source manifest is checked
before generation, simulator tests and the unsigned device archive. No App Store
upload or code-signing credential is used by this validation workflow.
