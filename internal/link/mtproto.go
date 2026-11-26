package link

import (
	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
	"github.com/Shu1t3/rospanel-shu1t3/internal/mtproto"
)

// MTProtoOn reports whether a server hands out its fake-TLS Telegram proxy: the lane is
// on, has a port, and is not left to the WEB proxy alone.
func MTProtoOn(set *model.Settings) bool { return set.MTProtoFakeTLSOn() }

// MTProtoWebProxyOn reports whether a server hands out its WEB proxy (Telegram Desktop
// 7.1+): the lane and its WEB switch on, on the server's own domain.
func MTProtoWebProxyOn(set *model.Settings) bool { return mtprotoWebHost(set) != "" }

// MTProtoAnyOn reports whether a server hands out its Telegram proxy in either form.
func MTProtoAnyOn(set *model.Settings) bool { return MTProtoOn(set) || MTProtoWebProxyOn(set) }

func mtprotoWebHost(set *model.Settings) string {
	if !set.MTProtoEnabled {
		return ""
	}
	return mtproto.WebHost(set.MTProtoWebHost())
}

// MTProto is a user's Telegram proxy link (tg://proxy), which adds the proxy to Telegram
// in one tap.
func MTProto(u model.User, set *model.Settings) string {
	return mtproto.Link(set.Host, set.MTProtoPort, set.MTProtoDomainOr(), u.UUID)
}

// MTProtoWeb is MTProto as an https://t.me/proxy address, for where tg:// does not open.
func MTProtoWeb(u model.User, set *model.Settings) string {
	return mtproto.WebLink(set.Host, set.MTProtoPort, set.MTProtoDomainOr(), u.UUID)
}

// MTProtoWebProxy is a user's WEB proxy link (tg://webproxy): the server's own domain and
// the user's "dd" secret, port 443 implied.
func MTProtoWebProxy(u model.User, set *model.Settings) string {
	return mtproto.WebProxyLink(mtprotoWebHost(set), u.UUID)
}

// MTProtoWebProxyWeb is MTProtoWebProxy as an https://t.me/webproxy address.
func MTProtoWebProxyWeb(u model.User, set *model.Settings) string {
	return mtproto.WebProxyWebLink(mtprotoWebHost(set), u.UUID)
}
