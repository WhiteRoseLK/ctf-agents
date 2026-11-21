---
name: ctf-connect
description: "Connect and authenticate to a CTF platform (CTFd, HackTheBox, RootMe, Sudocrypt). Usage: /ctf-connect <platform> [url] <token>"
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, and internet access.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch
metadata:
  user-invocable: "true"
---

# CTF Platform Connection

You are connecting to a CTF platform. Parse the user's arguments to extract:
- **platform**: `ctfd`, `htb`, `rootme`, or `sudocrypt`
- **url**: The platform base URL (required for `ctfd`, optional for `htb`/`rootme`/`sudocrypt`)
- **token**: The API token or session cookie

## Steps

1. Parse the arguments from `$ARGUMENTS`. The format is flexible:
   - `/ctf-connect ctfd https://ctf.example.com TOKEN123`
   - `/ctf-connect htb TOKEN123`
   - `/ctf-connect rootme SESSION_COOKIE`
   - `/ctf-connect sudocrypt SESSION_ID`

2. Run the connection command:
```bash
python3 ~/.claude/ctf/ctf_cli.py connect --platform <platform> --url <url> --token <token>
```
For HTB, RootMe, and Sudocrypt, `--url` is optional (built-in defaults are used).
The TLS certificate is verified by default. For a CTFd instance with a self-signed certificate only, add `--insecure` (applies to that instance's host, never to other platforms).

3. Report the result to the user:
   - If successful: show the number of available challenges
   - If error: show the error and suggest fixes (wrong token, wrong URL, etc.)

4. Store a note about the active connection so subsequent `/ctf-list` and `/ctf-solve` calls work.

## Platform-specific notes

### CTFd
- Token is found in: Settings > Access Tokens, or from the `session` cookie
- URL must be the base URL without trailing slash (e.g., `https://ctf.example.com`)

### HackTheBox
- Token from: Profile > Settings > App Tokens
- Uses `https://labs.hackthebox.com/api/v4` automatically

### RootMe
- Use the `spip_session` cookie value from browser
- Uses `https://api.www.root-me.org` automatically

### Sudocrypt
- Use the `session_id` cookie value from browser
- Uses `https://sudocrypt.com` automatically
