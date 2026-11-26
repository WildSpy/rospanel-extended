package link

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
)

// snellMethod is the cipher name Shadowrocket writes before the key in its own snell://
// export. Snell has no cipher to choose (v4 and up are AES-128-GCM); the name is only
// the form Shadowrocket reads back.
const snellMethod = "chacha20-ietf-poly1305"

// SnellOn reports whether a server hands out Snell to u: the lane is on and u has a port
// on it (a slot, handed out on the next config build after they first need one).
func SnellOn(set *model.Settings, u *model.User) bool { return set.SnellPort(u) > 0 }

// Snell is a user's Snell link in the form Shadowrocket exports and imports:
//
//	snell://base64url(chacha20-ietf-poly1305:<uuid>)@<host>:<port>?plugin=obfs-local;obfs=<http|tls>;obfs-host=<host>;obfs-uri=/&version=<5|6>&udp=1#<label>
//
// — the key is the user's UUID, the port theirs alone (model.SnellPortFor). The plugin
// is there only for a v5 lane with obfuscation; a v6 lane in unshaped mode says so in
// mode=, its default mode is the client's too.
func Snell(u model.User, set *model.Settings) string {
	port := set.SnellPort(&u)
	label := LabelFor(model.ProtoSnell, u, set)
	cred := base64.RawURLEncoding.EncodeToString([]byte(snellMethod + ":" + u.UUID))
	var q []string
	version := model.SnellVersionOr(set.SnellVersion)
	if version == model.SnellV5 {
		if obfs := model.SnellObfsOr(set.SnellObfs); obfs != model.SnellObfsNone {
			// As Shadowrocket writes it: only the "=" inside the plugin escaped.
			plugin := "obfs-local;obfs=" + obfs + ";obfs-host=" + model.SnellObfsHostOr(set.SnellObfsHost) + ";obfs-uri=/"
			q = append(q, "plugin="+strings.ReplaceAll(plugin, "=", "%3D"))
		}
	} else if mode := model.SnellModeOr(set.SnellMode); mode != model.SnellModeDefault {
		q = append(q, "mode="+mode)
	}
	q = append(q, "version="+strconv.Itoa(version), "udp=1")
	return fmt.Sprintf("snell://%s@%s?%s#%s", cred, net.JoinHostPort(set.Host, strconv.Itoa(port)),
		strings.Join(q, "&"), url.PathEscape(label))
}
