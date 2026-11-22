# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting:
open the **Security** tab of this repository and choose **Report a vulnerability**.

Do not open a public issue, pull request or discussion for a suspected vulnerability.

Useful details: the affected file or workflow, the steps to reproduce, and the
impact you expect (for example, a way to make the gate pass a change it should block).

## What the gate is and is not

The PR risk gate is a guard against mistakes. It is not a security boundary
against a determined attacker with write access, and it does not replace human
review, branch protection or code owner approval. See "Known limits" in
[README.md](README.md#known-limits) for the documented limits.

## Supported versions

Only the latest tagged release is supported. Fixes land on `main` and ship in
the next tagged release; older tags do not receive fixes.
