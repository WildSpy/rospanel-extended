package mtproto

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// The bridge page: what a Telegram app's hidden WebView loads from
// https://<host>/?bridge=<capability>#android=<nonce>. It holds no secret — only a
// one-use carrier token the relay minted for this load — and does nothing but move
// complete relay frames between the client and the carrier WebSocket.
//
// The two client boundaries it speaks (tdesktop web_proxy_webview.cpp, tproxy-server
// PROTOCOL.md "Client-to-bridge boundary"):
//
//   - the injected window.TelegramWebProxy of the hidden WebView: onmessage is set
//     before the {"t":"tproxy-android-init","v":1,"nonce":…} that makes the client send
//     HELLO; frames cross as ArrayBuffers, one complete frame per message (the client
//     takes the first message only if it is exactly one WELCOME); control values cross
//     as JSON strings, and the client's own control ({"t":"close"}) arrives as a string;
//   - the MessagePort a loopback parent page (the system-browser fallback) transfers
//     with {t:'tproxy-init',v:1}: whole batches cross as ArrayBuffers, control values as
//     objects.
//
// Nothing here may throw into the client's bridge — tdesktop fails the carrier on an
// exception — so every entry point is wrapped.

// webWSPath is the carrier WebSocket's path, as tproxy-server names it.
const webWSPath = "/api/v1/ws"

// webPageScript is the bridge script; TOKEN is filled in per load.
const webPageScript = `(function(){"use strict";
var TOKEN=%TOKEN%,PATH=%PATH%;
var MAX_FRAME=1048576,MAX_QUEUE=33554432;
var client=null,ws=null,wsOpen=false,adopted=false,dead=false,tries=0,pending=[],pendingBytes=0;
var m=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash||""),nonce=m?m[1]:null;
try{history.replaceState(null,"",location.pathname)}catch(e){}
function control(v){if(client&&!dead)try{client.control(v)}catch(e){}}
function status(s){control({t:"status",state:s})}
function finish(failed){
 if(dead)return;
 if(failed)status("failed");
 dead=true;pending=[];pendingBytes=0;
 var s=ws;ws=null;wsOpen=false;
 if(s)try{s.close(1000)}catch(e){}
 if(client)try{client.close()}catch(e){}
 client=null;
}
function known(t){return t===1||t===2||t===3||t===4||t===5||t===6||t===16||t===17||t===18||t===19||t===31}
function split(buf){
 var v=new DataView(buf),out=[],at=0;
 while(at<buf.byteLength){
  if(buf.byteLength-at<8||out.length>=4096)throw new Error("frame");
  var t=v.getUint8(at),n=v.getUint32(at+4),end=at+8+n;
  if(!known(t)||n>MAX_FRAME||end>buf.byteLength)throw new Error("frame");
  out.push({t:t,id:(v.getUint8(at+1)<<16)|(v.getUint8(at+2)<<8)|v.getUint8(at+3),n:n,b:buf.slice(at,end)});
  at=end;
 }
 if(!out.length)throw new Error("frame");
 return out;
}
function deliver(buf){
 var f;
 try{f=split(buf)}catch(e){finish(true);return}
 if(!adopted){
  if(f.length!==1||f[0].t!==17||f[0].id!==0||f[0].n!==0){finish(true);return}
  adopted=true;
 }
 try{
  if(client.native)for(var i=0;i<f.length;i++)client.binary(f[i].b);
  else client.binary(buf);
 }catch(e){finish(true)}
}
function send(buf){
 if(dead||!(buf instanceof ArrayBuffer)||!buf.byteLength)return;
 if(!wsOpen){
  if(pendingBytes+buf.byteLength>MAX_QUEUE){finish(true);return}
  pending.push(buf);pendingBytes+=buf.byteLength;return;
 }
 if(ws.bufferedAmount+buf.byteLength>MAX_QUEUE){finish(true);return}
 try{ws.send(buf)}catch(e){finish(true)}
}
function connect(){
 if(dead||ws)return;
 status(tries?"reconnecting":"connecting");
 var s,opened=false;
 try{s=new WebSocket("wss://"+location.host+PATH,"tproxy-v1."+TOKEN)}catch(e){finish(true);return}
 ws=s;s.binaryType="arraybuffer";
 s.onopen=function(){
  if(ws!==s||dead)return;
  opened=true;wsOpen=true;
  var q=pending;pending=[];pendingBytes=0;
  for(var i=0;i<q.length;i++)send(q[i]);
  status("connected");
 };
 s.onmessage=function(e){
  if(ws!==s||dead)return;
  var d=e.data;
  if(!(d instanceof ArrayBuffer)||!d.byteLength){finish(true);return}
  deliver(d);
 };
 s.onerror=function(){};
 s.onclose=function(){
  if(ws!==s)return;
  ws=null;wsOpen=false;
  if(dead)return;
  // The token is spent once the relay took the socket: only a carrier that never
  // opened may try again.
  if(opened||tries>=2){finish(true);return}
  tries++;setTimeout(connect,tries*1000);
 };
}
function useNative(b){
 if(client||dead)return;
 client={native:true,
  binary:function(v){b.postMessage(v)},
  control:function(v){b.postMessage(JSON.stringify(v))},
  close:function(){try{b.onmessage=null}catch(e){}}};
 b.onmessage=function(e){
  try{
   var v=e.data;
   if(typeof v==="string"){var o=null;try{o=JSON.parse(v)}catch(x){}if(o&&o.t==="close")finish(false);return}
   send(v);
  }catch(x){}
 };
 control({t:"tproxy-android-init",v:1,nonce:nonce});
 connect();
}
function usePort(p){
 if(client||dead)return;
 client={native:false,
  binary:function(v){p.postMessage(v,[v])},
  control:function(v){p.postMessage(v)},
  close:function(){try{p.onmessage=null;p.close()}catch(e){}}};
 p.onmessage=function(e){
  try{
   var v=e.data;
   if(v instanceof ArrayBuffer){send(v);return}
   if(v&&v.t==="close")finish(false);
  }catch(x){}
 };
 try{p.start()}catch(x){}
 connect();
}
addEventListener("message",function(e){
 try{
  if(client||dead||e.source!==parent||!e.data||typeof e.data!=="object")return;
  var k=Object.keys(e.data).sort();
  if(k.length!==2||k[0]!=="t"||k[1]!=="v"||e.data.t!=="tproxy-init"||e.data.v!==1||!e.ports||e.ports.length!==1)return;
  var o=new URL(e.origin);
  if(o.protocol!=="http:"||o.hostname!=="127.0.0.1"||!o.port||o.origin!==e.origin)return;
  usePort(e.ports[0]);
 }catch(x){}
});
addEventListener("pagehide",function(){finish(false)});
var native=null;
try{native=window.TelegramWebProxy}catch(e){}
if(native&&typeof native.postMessage==="function"&&nonce)useNative(native);
})();`

// webPageCSP is the bridge's Content-Security-Policy (tproxy-server's): only its own
// nonce'd script, connections to its own origin, and framing by a loopback parent — the
// system-browser fallback — and nothing else.
func webPageCSP(host, nonce string) string {
	return "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://" + host +
		"; font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; frame-src 'none'" +
		"; img-src 'none'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'nonce-" + nonce +
		"'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts"
}

// webPermissionsPolicy denies what the bridge never uses.
const webPermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), " +
	"display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), " +
	"payment=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()"

// serveWebPage writes the bridge page for one carrier token. token is base64url, so it
// needs no escaping inside the script's string literal.
func serveWebPage(w http.ResponseWriter, host, token string) {
	var n [18]byte
	_, _ = rand.Read(n[:])
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	script := strings.NewReplacer(`%TOKEN%`, `"`+token+`"`, `%PATH%`, `"`+webWSPath+`"`).Replace(webPageScript)
	body := `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1"><title>Connection</title></head>` +
		`<body><script nonce="` + nonce + `">` + script + `</script></body></html>`
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", webPageCSP(host, nonce))
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-DNS-Prefetch-Control", "off")
	h.Set("Permissions-Policy", webPermissionsPolicy)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
