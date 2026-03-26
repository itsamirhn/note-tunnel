# note-tunnel

TCP tunnel over note storage.

```
# server: forward tunnel to upstream
note-tunnel -role server -email rv@x.com -pass secret -addr 10.0.0.1:22

# client: listen locally, forward through tunnel
note-tunnel -role client -email rv@x.com -pass secret -addr 127.0.0.1:2222
```
