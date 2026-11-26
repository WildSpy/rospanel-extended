package sub

import "strings"

// SnellLinkFor reports whether a subscription client imports the snell:// link the
// panel writes (link.Snell, Shadowrocket's own export form): Shadowrocket, which reads
// Snell 1–6 (its User-Agent carries a build number, not the version, so any). Other
// clients' snell:// parsers differ in where the key goes and are not risked. An empty
// User-Agent is a hand-made request, which gets every form.
func SnellLinkFor(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	return ua == "" || strings.Contains(ua, "shadowrocket")
}
