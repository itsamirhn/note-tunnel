# note-tunnel

TCP tunnel over note storage.

## Build

```sh
task
```

## Setup

Both sides share a `seed`. Accounts are derived automatically.

**Server** (on VPS):

```sh
note-tunnel -role server -seed mysecret -addr 127.0.0.1:1080
```

**Client** (locally):

```sh
note-tunnel -role client -seed mysecret -addr 127.0.0.1:8080
```

## SOCKS proxy

Run a SOCKS5 listener on the server (e.g. `ssh -D 127.0.0.1:1080 -N localhost`), start note-tunnel pointing at it, then configure your browser or system proxy to SOCKS5 `127.0.0.1:8080`.

## psst

There's one more thing the binary needs before it wakes up.
If you know what it is, you'll have a great time.
If you don't, find me and ask nicely. Maybe I'll leave a breadcrumb.
