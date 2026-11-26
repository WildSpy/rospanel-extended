-- The WEB proxy of Telegram Desktop 7.1+ beside the MTProto lane (internal/mtproto
-- web.go): the master's switch, and whether it keeps the fake-TLS port at all. A node's
-- switches ride in its connections; serves_mtproto_web is whether its agent said it
-- answers the WEB proxy (an older one does not).
ALTER TABLE settings ADD COLUMN mtproto_web        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN mtproto_web_only   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes    ADD COLUMN serves_mtproto_web INTEGER NOT NULL DEFAULT 0;
