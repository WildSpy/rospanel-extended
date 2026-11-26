# sing-snell v5 server, vendored

`snellv5`, `internal/eof` and `internal/reuse` are copied verbatim from
[SagerNet/sing-snell](https://github.com/SagerNet/sing-snell) at
`v0.0.0-20261125221246-3f5050388f83` (GPL-3.0-or-later, see `LICENSE`), with the import
paths of its internal packages rewritten. The rest of the library (the root package,
`snellv6`) is used from the module as is.

One patch, in `snellv5/server.go`: `ServiceOptions.SaltCache` lets services share one
first-record salt replay cache. Upstream each `Service` owns one — two Bloom
generations of 500 000 entries, ~6 MiB once used — and RosPanel runs a service per user (a Snell client names its user
only by the PSK, so each user has a port and a service
of their own).

To update: copy the same files from the new version, rewrite the imports again, and
re-apply the patch (search for "RosPanel patch").
