# gitPuller
A Python3 script to recursively backup Git repositories by pulling the latest changes for local and remote branches. It handles authentication gracefully, allowing password or SSH key usage only when needed.

---

## Features

- Recursively discovers Git repositories in a directory tree.
- Pulls updates for:
  - All local branches.
  - Remote branches (optional via `--all`).
- Graceful authentication handling:
  - Attempts `git pull` without credentials first.
  - Only uses credentials if authentication fails.
- Supports both password (`-p`) and SSH key (`-s`) authentication.
- Infinite or limited recursion depth for subdirectories.
- Color-coded output for easy readability.

---

## Requirements

- Python 3.6+
- Git installed and accessible in `PATH`.

---

## Usage

```bash
./backup_git.py [options]
