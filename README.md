# SecretShield

SecretShield is a Python security scanner for detecting accidentally exposed secrets and credentials in source code, configuration files, and Git repositories.

## Status

Early development.

## Goals

- Detect common API keys, tokens, passwords, private keys, and database credentials
- Detect high-entropy suspicious strings
- Safely mask detected secrets
- Scan repositories efficiently
- Produce JSON and Markdown audit reports

## Security

Never place real credentials in this repository. Use synthetic test secrets only.
