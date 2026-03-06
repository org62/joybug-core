---
allowed-tools: Read, Grep, Glob, Edit, Write, Bash(git diff:*), Bash(git status:*), Bash(git log:*)
description: Review staged code for bugs and fix issues
---

Review the currently staged (git-added) code for bugs, code duplication, and long-term maintainability issues. Fix everything you find by editing the source files directly.

## Staged diff to review

$!git diff --cached$

## Instructions

1. Carefully analyze the staged diff above for:
   - **Bugs**: Logic errors, off-by-one errors, null/undefined risks, race conditions, missing error handling at system boundaries, security vulnerabilities
   - **Simplification**: Code that can be made shorter or clearer — redundant variables, unnecessary nesting, verbose patterns that have idiomatic alternatives, conditions that can be collapsed
   - **Code duplication**: Repeated logic that should be extracted, copy-paste patterns
   - **Maintainability**: Unclear naming, overly complex control flow, missing cleanup patterns (e.g. session cleanup per project conventions), inconsistent patterns compared to surrounding code

2. For each issue found, edit the source files to fix it. Use `Read` to see full file context before making changes.

3. **CRITICAL: Do NOT run `git add` or stage any changes.** Only read files and edit them. The user will review and stage fixes themselves.

4. After fixing, summarize what you changed and why.
