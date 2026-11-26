-- Snell v5/v6 (internal/snell): the master's switch and settings, and each user's slot
-- in every server's port range (a Snell client names its user by the key alone, so a
-- user has a port of their own: the server's base plus the slot). A node's switch is
-- snell_enabled (NULL until set, like the other lanes); the rest rides in its
-- connections; serves_snell is whether its agent said it answers Snell.
ALTER TABLE settings ADD COLUMN snell_enabled   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN snell_version   INTEGER NOT NULL DEFAULT 5;
ALTER TABLE settings ADD COLUMN snell_obfs      TEXT    NOT NULL DEFAULT 'none';
ALTER TABLE settings ADD COLUMN snell_obfs_host TEXT    NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN snell_mode      TEXT    NOT NULL DEFAULT 'default';
ALTER TABLE settings ADD COLUMN snell_port_base INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN snell_name      TEXT    NOT NULL DEFAULT '';
ALTER TABLE nodes    ADD COLUMN snell_enabled   INTEGER;
ALTER TABLE nodes    ADD COLUMN serves_snell    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users    ADD COLUMN snell_slot      INTEGER NOT NULL DEFAULT 0;
