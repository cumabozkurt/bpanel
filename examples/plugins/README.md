# Example plugin

`hello/` is the smallest valid BPanel plugin (one static page). `sign/` creates
ed25519 keys and signed archives:

    go run ./examples/plugins/sign keygen -out mykey
    go run ./examples/plugins/sign pack -key mykey -dir examples/plugins/hello -out hello-1.0.0.tar.gz

Trust `mykey.pub` under **Plugins → Trusted signing keys**, then upload the
archive. Keep `mykey` (the private seed) secret. See docs/plugins.md.
