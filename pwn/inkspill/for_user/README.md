# inkspill

A newsroom tip line prints every submitted report before an editor reviews it.
Can you convince the press to release its protected archive?

Run locally:

```sh
docker compose up --build
nc 127.0.0.1 31338
```

The service is x86-64 and each connection has a 30-second timeout. Matching
`libc.so.6` and `ld-linux-x86-64.so.2` files are included for analysis.
