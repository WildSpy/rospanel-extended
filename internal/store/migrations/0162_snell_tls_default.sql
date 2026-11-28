-- Snell v5 starts with TLS obfuscation. Without it, like v6, a Snell stream is random
-- bytes from the first packet, which DPI in Russia drops (v6 measured: 17 of 20
-- connections lost on the first packet); obfs=tls passes as HTTPS. Only a server that
-- has not turned Snell on yet: one that runs it keeps what its operator chose.
UPDATE settings SET snell_obfs = 'tls' WHERE snell_enabled = 0 AND snell_obfs = 'none';
