# Temporary

A password-protected chat room at **https://mayankvekariya.de/temporary/**

Open the page, type the room password, and share text or files with whoever else
knows the password. Works on any phone or laptop, no login.

## How it works

- This repo (`temporary`) is only the page. It holds no messages.
- Messages and files live in the public repo `temporary-data`, **encrypted**
  in the browser with the room password (PBKDF2-SHA256 + AES-256-GCM).
  Without the password the data there is unreadable.
- The password also unlocks a GitHub key that can only write to `temporary-data`,
  so friends can send without any GitHub account.
- New messages show up within about 3 seconds.

## Owner tasks

- **Set up / change password:** on the lock screen, "Set up the room or change the
  password". Paste the `temporary-data` key and choose a password (12+ characters).
  A new password clears the room and locks everyone else out.
- **Clear room:** button in the header. Removes every message and file, including
  from the repo history.
- **Key expired?** Create a new fine-grained token (only `temporary-data`,
  Contents: read and write) and run setup again.

## Limits

Files up to 25 MB. Anyone with the password can read, send and clear.

## Tests

```
npm i -D playwright && npx playwright install chromium
node tests/e2e.mjs
```
Runs the page against a local fake GitHub with two people in the room.
