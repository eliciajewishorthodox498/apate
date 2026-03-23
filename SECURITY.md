# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in Apate, please **do not** open a public issue.

Email: david@netviper.gr

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

You'll get a response within 48 hours.

## Scope

Apate is a source code obfuscator, not an encryption tool. The security model is documented in the README. Specifically:

- The AES-256-GCM encrypted manifest is intended to be cryptographically secure
- The obfuscated source code is intended to be *hard to read*, not *impossible to reverse-engineer*
- If you can reverse-engineer obfuscated output without the key, that's expected behavior, not a vulnerability

If you find a way to decrypt the `.apate` manifest without the key, *that's* a vulnerability. Report it.
