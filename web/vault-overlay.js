(function() {
    var overlay = document.createElement("div");
    overlay.setAttribute("id","overlay");
    overlay.setAttribute("style", "background-color: #000; opacity: .7; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 10;");

    var hidden = document.createElement("div");
    hidden.setAttribute("style", "display: none;");
    overlay.appendChild(hidden);

    var service = document.createElement("input");
    service.id = "service";
    service.value = window.location.hostname;
//    if (service.value) {
//        service.setAttribute("readonly", "readonly");
//    }
    service.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(service);

    var passphrase = document.createElement("input");
    passphrase.id = "passphrase";
    passphrase.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(passphrase);

    var passphrase_text = document.createElement("input");
    passphrase_text.id = "passphrase-text";
    hidden.appendChild(passphrase_text);

    var show_passphrase = document.createElement("input");
    show_passphrase.type = "checkbox";
    show_passphrase.id = "show-passphrase";
    hidden.appendChild(show_passphrase);

    var length = document.createElement("input");
    length.id = "vlength";
    length.value = "20";
    hidden.appendChild(length);

    var repeat = document.createElement("input");
    repeat.id = "repeat";
    repeat.value = "2";
    hidden.appendChild(repeat);

    var required = document.createElement("input");
    required.id = "required";
    required.value = "2";
    hidden.appendChild(required);

    var word = document.createElement("input");
    word.setAttribute("id", "word");
    word.setAttribute("readonly", "readonly");
    word.setAttribute("style", "float: right; clear: right;");
    overlay.appendChild(word);

    document.body.appendChild(overlay);

    var inputs = document.getElementsByTagName('input'), input;
    for (var i = 0, n = inputs.length; i < n; i++) {
        var input = inputs[i];
        if (input.type == "password") {
            console.log("password form found: " + input.id);
            var copynclose = function(input){
                return function(e){
                    if (e.keyCode === 13) {
                        input.value = word.value;
                        console.log("copying generated password to " + input.id);
                        document.body.removeChild(overlay);
                    }
                }
            }
            service.addEventListener("keydown", copynclose(input), false);
            passphrase.addEventListener("keydown", copynclose(input), false);
        }
    }
})();
/*
CryptoJS v3.1.2
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/

// Core
var CryptoJS=CryptoJS||function(g,j){var e={},d=e.lib={},m=function(){},n=d.Base={extend:function(a){m.prototype=this;var c=new m;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
q=d.WordArray=n.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=j?c:4*a.length},toString:function(a){return(a||l).stringify(this)},concat:function(a){var c=this.words,p=a.words,f=this.sigBytes;a=a.sigBytes;this.clamp();if(f%4)for(var b=0;b<a;b++)c[f+b>>>2]|=(p[b>>>2]>>>24-8*(b%4)&255)<<24-8*((f+b)%4);else if(65535<p.length)for(b=0;b<a;b+=4)c[f+b>>>2]=p[b>>>2];else c.push.apply(c,p);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
32-8*(c%4);a.length=g.ceil(c/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*g.random()|0);return new q.init(c,a)}}),b=e.enc={},l=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++){var d=c[f>>>2]>>>24-8*(f%4)&255;b.push((d>>>4).toString(16));b.push((d&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f+=2)b[f>>>3]|=parseInt(a.substr(f,
2),16)<<24-4*(f%8);return new q.init(b,c/2)}},k=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++)b.push(String.fromCharCode(c[f>>>2]>>>24-8*(f%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f++)b[f>>>2]|=(a.charCodeAt(f)&255)<<24-8*(f%4);return new q.init(b,c)}},h=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(b){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},
u=d.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=new q.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=h.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var b=this._data,d=b.words,f=b.sigBytes,l=this.blockSize,e=f/(4*l),e=a?g.ceil(e):g.max((e|0)-this._minBufferSize,0);a=e*l;f=g.min(4*a,f);if(a){for(var h=0;h<a;h+=l)this._doProcessBlock(d,h);h=d.splice(0,a);b.sigBytes-=f}return new q.init(h,f)},clone:function(){var a=n.clone.call(this);
a._data=this._data.clone();return a},_minBufferSize:0});d.Hasher=u.extend({cfg:n.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){u.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,d){return(new a.init(d)).finalize(b)}},_createHmacHelper:function(a){return function(b,d){return(new w.HMAC.init(a,
d)).finalize(b)}}});var w=e.algo={};return e}(Math);

// SHA1
(function(){var g=CryptoJS,j=g.lib,e=j.WordArray,d=j.Hasher,m=[],j=g.algo.SHA1=d.extend({_doReset:function(){this._hash=new e.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(d,e){for(var b=this._hash.words,l=b[0],k=b[1],h=b[2],g=b[3],j=b[4],a=0;80>a;a++){if(16>a)m[a]=d[e+a]|0;else{var c=m[a-3]^m[a-8]^m[a-14]^m[a-16];m[a]=c<<1|c>>>31}c=(l<<5|l>>>27)+j+m[a];c=20>a?c+((k&h|~k&g)+1518500249):40>a?c+((k^h^g)+1859775393):60>a?c+((k&h|k&g|h&g)-1894007588):c+((k^h^
g)-899497514);j=g;g=h;h=k<<30|k>>>2;k=l;l=c}b[0]=b[0]+l|0;b[1]=b[1]+k|0;b[2]=b[2]+h|0;b[3]=b[3]+g|0;b[4]=b[4]+j|0},_doFinalize:function(){var d=this._data,e=d.words,b=8*this._nDataBytes,l=8*d.sigBytes;e[l>>>5]|=128<<24-l%32;e[(l+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(l+64>>>9<<4)+15]=b;d.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=d.clone.call(this);e._hash=this._hash.clone();return e}});g.SHA1=d._createHelper(j);g.HmacSHA1=d._createHmacHelper(j)})();

// SHA256
(function(h){for(var s=CryptoJS,f=s.lib,g=f.WordArray,q=f.Hasher,f=s.algo,m=[],r=[],l=function(a){return 4294967296*(a-(a|0))|0},k=2,n=0;64>n;){var j;a:{j=k;for(var u=h.sqrt(j),t=2;t<=u;t++)if(!(j%t)){j=!1;break a}j=!0}j&&(8>n&&(m[n]=l(h.pow(k,0.5))),r[n]=l(h.pow(k,1/3)),n++);k++}var a=[],f=f.SHA256=q.extend({_doReset:function(){this._hash=new g.init(m.slice(0))},_doProcessBlock:function(c,d){for(var b=this._hash.words,e=b[0],f=b[1],g=b[2],j=b[3],h=b[4],m=b[5],n=b[6],q=b[7],p=0;64>p;p++){if(16>p)a[p]=
c[d+p]|0;else{var k=a[p-15],l=a[p-2];a[p]=((k<<25|k>>>7)^(k<<14|k>>>18)^k>>>3)+a[p-7]+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+a[p-16]}k=q+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+(h&m^~h&n)+r[p]+a[p];l=((e<<30|e>>>2)^(e<<19|e>>>13)^(e<<10|e>>>22))+(e&f^e&g^f&g);q=n;n=m;m=h;h=j+k|0;j=g;g=f;f=e;e=k+l|0}b[0]=b[0]+e|0;b[1]=b[1]+f|0;b[2]=b[2]+g|0;b[3]=b[3]+j|0;b[4]=b[4]+h|0;b[5]=b[5]+m|0;b[6]=b[6]+n|0;b[7]=b[7]+q|0},_doFinalize:function(){var a=this._data,d=a.words,b=8*this._nDataBytes,e=8*a.sigBytes;
d[e>>>5]|=128<<24-e%32;d[(e+64>>>9<<4)+14]=h.floor(b/4294967296);d[(e+64>>>9<<4)+15]=b;a.sigBytes=4*d.length;this._process();return this._hash},clone:function(){var a=q.clone.call(this);a._hash=this._hash.clone();return a}});s.SHA256=q._createHelper(f);s.HmacSHA256=q._createHmacHelper(f)})(Math);

// HMAC
(function(){var h=CryptoJS,s=h.enc.Utf8;h.algo.HMAC=h.lib.Base.extend({init:function(f,g){f=this._hasher=new f.init;"string"==typeof g&&(g=s.parse(g));var h=f.blockSize,m=4*h;g.sigBytes>m&&(g=f.finalize(g));g.clamp();for(var r=this._oKey=g.clone(),l=this._iKey=g.clone(),k=r.words,n=l.words,j=0;j<h;j++)k[j]^=1549556828,n[j]^=909522486;r.sigBytes=l.sigBytes=m;this.reset()},reset:function(){var f=this._hasher;f.reset();f.update(this._iKey)},update:function(f){this._hasher.update(f);return this},finalize:function(f){var g=
this._hasher;f=g.finalize(f);g.reset();return g.finalize(this._oKey.clone().concat(f))}})})();

// PBKDF2
(function(){var g=CryptoJS,j=g.lib,e=j.Base,d=j.WordArray,j=g.algo,m=j.HMAC,n=j.PBKDF2=e.extend({cfg:e.extend({keySize:4,hasher:j.SHA1,iterations:1}),init:function(d){this.cfg=this.cfg.extend(d)},compute:function(e,b){for(var g=this.cfg,k=m.create(g.hasher,e),h=d.create(),j=d.create([1]),n=h.words,a=j.words,c=g.keySize,g=g.iterations;n.length<c;){var p=k.update(b).finalize(j);k.reset();for(var f=p.words,v=f.length,s=p,t=1;t<g;t++){s=k.finalize(s);k.reset();for(var x=s.words,r=0;r<v;r++)f[r]^=x[r]}h.concat(p);
a[0]++}h.sigBytes=4*c;return h}});g.PBKDF2=function(d,b,e){return n.create(e).compute(d,b)}})();

// Encoding
(function(){var u=CryptoJS,p=u.lib.WordArray;u.enc.Base64={stringify:function(d){var l=d.words,p=d.sigBytes,t=this._map;d.clamp();d=[];for(var r=0;r<p;r+=3)for(var w=(l[r>>>2]>>>24-8*(r%4)&255)<<16|(l[r+1>>>2]>>>24-8*((r+1)%4)&255)<<8|l[r+2>>>2]>>>24-8*((r+2)%4)&255,v=0;4>v&&r+0.75*v<p;v++)d.push(t.charAt(w>>>6*(3-v)&63));if(l=t.charAt(64))for(;d.length%4;)d.push(l);return d.join("")},parse:function(d){var l=d.length,s=this._map,t=s.charAt(64);t&&(t=d.indexOf(t),-1!=t&&(l=t));for(var t=[],r=0,w=0;w<
l;w++)if(w%4){var v=s.indexOf(d.charAt(w-1))<<2*(w%4),b=s.indexOf(d.charAt(w))>>>6-2*(w%4);t[r>>>2]|=(v|b)<<24-8*(r%4);r++}return p.create(t,r)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();

// Cipher
CryptoJS.lib.Cipher||function(u){var p=CryptoJS,d=p.lib,l=d.Base,s=d.WordArray,t=d.BufferedBlockAlgorithm,r=p.enc.Base64,w=p.algo.EvpKDF,v=d.Cipher=t.extend({cfg:l.extend(),createEncryptor:function(e,a){return this.create(this._ENC_XFORM_MODE,e,a)},createDecryptor:function(e,a){return this.create(this._DEC_XFORM_MODE,e,a)},init:function(e,a,b){this.cfg=this.cfg.extend(b);this._xformMode=e;this._key=a;this.reset()},reset:function(){t.reset.call(this);this._doReset()},process:function(e){this._append(e);return this._process()},
finalize:function(e){e&&this._append(e);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(e){return{encrypt:function(b,k,d){return("string"==typeof k?c:a).encrypt(e,b,k,d)},decrypt:function(b,k,d){return("string"==typeof k?c:a).decrypt(e,b,k,d)}}}});d.StreamCipher=v.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var b=p.mode={},x=function(e,a,b){var c=this._iv;c?this._iv=u:c=this._prevBlock;for(var d=0;d<b;d++)e[a+d]^=
c[d]},q=(d.BlockCipherMode=l.extend({createEncryptor:function(e,a){return this.Encryptor.create(e,a)},createDecryptor:function(e,a){return this.Decryptor.create(e,a)},init:function(e,a){this._cipher=e;this._iv=a}})).extend();q.Encryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize;x.call(this,e,a,c);b.encryptBlock(e,a);this._prevBlock=e.slice(a,a+c)}});q.Decryptor=q.extend({processBlock:function(e,a){var b=this._cipher,c=b.blockSize,d=e.slice(a,a+c);b.decryptBlock(e,a);x.call(this,
e,a,c);this._prevBlock=d}});b=b.CBC=q;q=(p.pad={}).Pkcs7={pad:function(a,b){for(var c=4*b,c=c-a.sigBytes%c,d=c<<24|c<<16|c<<8|c,l=[],n=0;n<c;n+=4)l.push(d);c=s.create(l,c);a.concat(c)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};d.BlockCipher=v.extend({cfg:v.cfg.extend({mode:b,padding:q}),reset:function(){v.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var c=a.createEncryptor;else c=a.createDecryptor,this._minBufferSize=1;this._mode=c.call(a,
this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var n=d.CipherParams=l.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),b=(p.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext;a=a.salt;return(a?s.create([1398893684,
1701076831]).concat(a).concat(b):b).toString(r)},parse:function(a){a=r.parse(a);var b=a.words;if(1398893684==b[0]&&1701076831==b[1]){var c=s.create(b.slice(2,4));b.splice(0,4);a.sigBytes-=16}return n.create({ciphertext:a,salt:c})}},a=d.SerializableCipher=l.extend({cfg:l.extend({format:b}),encrypt:function(a,b,c,d){d=this.cfg.extend(d);var l=a.createEncryptor(c,d);b=l.finalize(b);l=l.cfg;return n.create({ciphertext:b,key:c,iv:l.iv,algorithm:a,mode:l.mode,padding:l.padding,blockSize:a.blockSize,formatter:d.format})},
decrypt:function(a,b,c,d){d=this.cfg.extend(d);b=this._parse(b,d.format);return a.createDecryptor(c,d).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a,this):a}}),p=(p.kdf={}).OpenSSL={execute:function(a,b,c,d){d||(d=s.random(8));a=w.create({keySize:b+c}).compute(a,d);c=s.create(a.words.slice(b),4*c);a.sigBytes=4*b;return n.create({key:a,iv:c,salt:d})}},c=d.PasswordBasedCipher=a.extend({cfg:a.cfg.extend({kdf:p}),encrypt:function(b,c,d,l){l=this.cfg.extend(l);d=l.kdf.execute(d,
b.keySize,b.ivSize);l.iv=d.iv;b=a.encrypt.call(this,b,c,d.key,l);b.mixIn(d);return b},decrypt:function(b,c,d,l){l=this.cfg.extend(l);c=this._parse(c,l.format);d=l.kdf.execute(d,b.keySize,b.ivSize,c.salt);l.iv=d.iv;return a.decrypt.call(this,b,c,d.key,l)}})}();

// AES
(function(){for(var u=CryptoJS,p=u.lib.BlockCipher,d=u.algo,l=[],s=[],t=[],r=[],w=[],v=[],b=[],x=[],q=[],n=[],a=[],c=0;256>c;c++)a[c]=128>c?c<<1:c<<1^283;for(var e=0,j=0,c=0;256>c;c++){var k=j^j<<1^j<<2^j<<3^j<<4,k=k>>>8^k&255^99;l[e]=k;s[k]=e;var z=a[e],F=a[z],G=a[F],y=257*a[k]^16843008*k;t[e]=y<<24|y>>>8;r[e]=y<<16|y>>>16;w[e]=y<<8|y>>>24;v[e]=y;y=16843009*G^65537*F^257*z^16843008*e;b[k]=y<<24|y>>>8;x[k]=y<<16|y>>>16;q[k]=y<<8|y>>>24;n[k]=y;e?(e=z^a[a[a[G^z]]],j^=a[a[j]]):e=j=1}var H=[0,1,2,4,8,
16,32,64,128,27,54],d=d.AES=p.extend({_doReset:function(){for(var a=this._key,c=a.words,d=a.sigBytes/4,a=4*((this._nRounds=d+6)+1),e=this._keySchedule=[],j=0;j<a;j++)if(j<d)e[j]=c[j];else{var k=e[j-1];j%d?6<d&&4==j%d&&(k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255]):(k=k<<8|k>>>24,k=l[k>>>24]<<24|l[k>>>16&255]<<16|l[k>>>8&255]<<8|l[k&255],k^=H[j/d|0]<<24);e[j]=e[j-d]^k}c=this._invKeySchedule=[];for(d=0;d<a;d++)j=a-d,k=d%4?e[j]:e[j-4],c[d]=4>d||4>=j?k:b[l[k>>>24]]^x[l[k>>>16&255]]^q[l[k>>>
8&255]]^n[l[k&255]]},encryptBlock:function(a,b){this._doCryptBlock(a,b,this._keySchedule,t,r,w,v,l)},decryptBlock:function(a,c){var d=a[c+1];a[c+1]=a[c+3];a[c+3]=d;this._doCryptBlock(a,c,this._invKeySchedule,b,x,q,n,s);d=a[c+1];a[c+1]=a[c+3];a[c+3]=d},_doCryptBlock:function(a,b,c,d,e,j,l,f){for(var m=this._nRounds,g=a[b]^c[0],h=a[b+1]^c[1],k=a[b+2]^c[2],n=a[b+3]^c[3],p=4,r=1;r<m;r++)var q=d[g>>>24]^e[h>>>16&255]^j[k>>>8&255]^l[n&255]^c[p++],s=d[h>>>24]^e[k>>>16&255]^j[n>>>8&255]^l[g&255]^c[p++],t=
d[k>>>24]^e[n>>>16&255]^j[g>>>8&255]^l[h&255]^c[p++],n=d[n>>>24]^e[g>>>16&255]^j[h>>>8&255]^l[k&255]^c[p++],g=q,h=s,k=t;q=(f[g>>>24]<<24|f[h>>>16&255]<<16|f[k>>>8&255]<<8|f[n&255])^c[p++];s=(f[h>>>24]<<24|f[k>>>16&255]<<16|f[n>>>8&255]<<8|f[g&255])^c[p++];t=(f[k>>>24]<<24|f[n>>>16&255]<<16|f[g>>>8&255]<<8|f[h&255])^c[p++];n=(f[n>>>24]<<24|f[g>>>16&255]<<16|f[h>>>8&255]<<8|f[k&255])^c[p++];a[b]=q;a[b+1]=s;a[b+2]=t;a[b+3]=n},keySize:8});u.AES=p._createHelper(d)})();

if (typeof module === 'object') module.exports = CryptoJS;

(function() {
'use strict';

var indexOf = function(list, needle) {
  if (list.indexOf) return list.indexOf(needle);
  for (var i = 0, n = list.length; i < n; i++) {
    if (list[i] === needle) return i;
  }
  return -1;
};

var Base64 = {
  CHARS: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split(''),

  decode: function(string) {
    var data  = [],
        chars = Base64.CHARS,
        n     = string.length,
        i, c, offset, chunk, padding;

    for (offset = 0; offset < n; offset += 4) {
      chunk   = 0;
      padding = 0;

      for (i = 0; i < 4; i++) {
        c = string[offset + i];
        if (c === '=') {
          padding += 1;
        } else {
          chunk |= indexOf(chars, c) << 6 * (3 - i);
        }
      }
      for (i = 0; i < 3 - padding; i++) {
        data.push((chunk >>> 8 * (2 - i)) % 0x100);
      }
    }

    return String.fromCharCode.apply(String, data);
  },

  encode: function(data) {
    var string = '',
        chars  = Base64.CHARS,
        n      = data.length,
        i, c, offset, chunk, padding;

    for (offset = 0; offset < n; offset += 3) {
      chunk   = 0;
      padding = 0;

      for (i = 0; i < 3; i++) {
        c = data.charCodeAt(offset + i);
        if (isNaN(c)) {
          padding += 1;
        } else {
          chunk |= c << 8 * (2 - i);
        }
      }
      for (i = 0; i < 4 - padding; i++) {
        string += chars[(chunk >>> 6 * (3 - i)) % 0x40];
      }
      while (padding--) string += '=';
    }

    return string;
  }
};

var Binary = {
  decode: function(string) {
    return string;
  },

  encode: function(data) {
    return data;
  }
};

var Hex = {
  decode: function(string) {
    var data = [];
    for (var i = 0, n = string.length; i < n; i += 2) {
      data[i / 2] = parseInt(string.substr(i, 2), 16);
    }
    return String.fromCharCode.apply(String, data);
  },

  encode: function(data) {
    var string = '', block;
    for (var i = 0, n = data.length; i < n; i++) {
      block = data.charCodeAt(i).toString(16);

      if (block.length === 1) block = '0' + block;

      if (block.length > 2)
        throw new Error('Hex encoding error: Found value ' + block + ' at offset ' + i);

      string += block;
    }
    return string;
  }
};

var UTF8 = {
  decode: function(string) {
    var data = [],
        n    = string.length,
        c, d;

    for (var i = 0; i < string.length; i++) {
      c = string.charCodeAt(i);

      if (c >= 0xd800 && c <= 0xdbff) {
        d = string.charCodeAt(i + 1);
        if (isNaN(d) || d < 0xdc00 || d > 0xdfff) {
          throw new Error('Illegal low surrogate ' + d + ' at offset ' + i);
        }
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i += 1;
      } 

      if (c <= 0x7f) {
        data.push(c);
      } else if (c <= 0x7ff) {
        data.push(0xc0 | (c >>>  6), 0x80 | c % 0x40);
      } else if (c <= 0xffff) {
        data.push(0xe0 | (c >>> 12), 0x80 | (c >>>  6) % 0x40, 0x80 | c % 0x40);
      } else if (c <= 0x10ffff) {
        data.push(0xf0 | (c >>> 18), 0x80 | (c >>> 12) % 0x40, 0x80 | (c >>> 6) % 0x40, 0x80 | c % 0x40);
      } else {
        throw new Error('UTF-8 encoding error: Illegal code point ' + c + ' at offset ' + i);
      }
    }

    return String.fromCharCode.apply(String, data);
  },

  encode: function(data) {
    var codepoints = [],
        offset     = 0,
        n          = data.length,
        b, c;

    while (offset < n) {
      b = [
        data.charCodeAt(offset),
        data.charCodeAt(offset + 1),
        data.charCodeAt(offset + 2),
        data.charCodeAt(offset + 3)
      ];

      b = [b[0], (b[1] & 0x80 ? b[1] : NaN), (b[2] & 0x80 ? b[2] : NaN), (b[3] & 0x80 ? b[3] : NaN)];
      c = b[0];

      if (c <= 127) {
        offset += 1;
      } else if (c <= 223) {
        c = (b[0] % 0x20 <<  6) + (b[1] % 0x40);
        offset += 2;
      } else if (c <= 239) {
        c = (b[0] % 0x10 << 12) + (b[1] % 0x40 <<  6) + (b[2] % 0x40);
        offset += 3;
      } else if (c <= 244) {
        c = (b[0] % 0x08 << 18) + (b[1] % 0x40 << 12) + (b[2] % 0x40 << 6) + (b[3] % 0x40);
        offset += 4;
      } else {
        throw new Error('UTF-8 encoding error: Illegal leading byte ' + c + ' at offset ' + offset);
      }

      if (isNaN(c))
        throw new Error('UTF-8 encoding error: Insufficient bytes at offset ' + offset);
      if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
        throw new Error('UTF-8 encoding error: Illegal code point ' + c + ' at offset ' + offset);

      if (c <= 0xffff) {
        codepoints.push(c);
      } else {
        c -= 0x10000;
        codepoints.push(0xd800 + (c >>> 10), 0xdc00 + (c % 0x400));
      }
    }

    return String.fromCharCode.apply(String, codepoints);
  }
};

var Buffer = function(data, encoding) {
  if (!(this instanceof Buffer)) return new Buffer(data, encoding);

  if (data instanceof Buffer) {
    data = data._data;
  } else if (data instanceof Array) {
    data = String.fromCharCode.apply(String, data);
  } else if (typeof data === 'number') {
    data = String.fromCharCode.apply(String, Array(data));
  } else if (typeof data === 'string') {
    encoding = encoding || 'utf8';
    data = Buffer.ENCODERS[encoding].decode(data);
  }
  this._data  = data;
  this.length = data.length;
};

Buffer.ENCODERS = {
  base64: Base64,
  binary: Binary,
  hex:    Hex,
  utf8:   UTF8
};

Buffer.concat = function(list, totalLength, BufferClass) {
  var i, n;

  if (typeof totalLength !== 'number') {
    totalLength = 0;
    for (i = 0, n = list.length; i < n; i++) {
      totalLength += list[i].length;
    }
  }

  BufferClass = BufferClass || Buffer;

  var buffer = new BufferClass(totalLength),
      offset = 0;

  for (i = 0, n = list.length; i < n; i++) {
    list[i].copy(buffer, offset);
    offset += list[i].length;
  }
  return buffer;
};

Buffer.prototype.copy = function(target, targetStart, sourceStart, sourceEnd) {
  targetStart = targetStart || 0;
  sourceStart = sourceStart || 0;
  sourceEnd   = sourceEnd   || this._data.length;

  target._data = target._data.substring(0, targetStart) +
                 this._data.substring(sourceStart, sourceEnd) +
                 target._data.substring(targetStart + sourceEnd - sourceStart, target._data.length);

  target.length = target._data.length;
};

Buffer.prototype.inspect = function() {
  return '<Buffer ' + this.toString('hex').match(/../g).join(' ') + '>';
};

Buffer.prototype.slice = function(start, end) {
  return new Buffer(this._data.substring(start, end), 'binary');
};

Buffer.prototype.toString = function(encoding) {
  encoding = encoding || 'utf8';
  return Buffer.ENCODERS[encoding].encode(this._data);
};

if (typeof module !== 'undefined')
  module.exports = Buffer;
else if (typeof window !== 'undefined')
  window.Buffer = Buffer;

})();

var crypto_shim = {
  createCipheriv: function(cipherMode, key, iv) {
    return new crypto_shim.Cipher(cipherMode, new Buffer(key, 'binary'), new Buffer(iv, 'binary'));
  },

  createDecipheriv: function(cipherMode, key, iv) {
    return new crypto_shim.Decipher(cipherMode, new Buffer(key, 'binary'), new Buffer(iv, 'binary'));
  },

  createHmac: function(hashMode, key) {
    return new crypto_shim.Hmac(hashMode, new Buffer(key, 'binary'));
  },

  pbkdf2: function(password, salt, work, keyBytes, callback) {
    var key    = CryptoJS.PBKDF2(password, salt, {keySize: keyBytes/4, iterations: work}),
        buffer = new Buffer(key.toString(CryptoJS.enc.Hex), 'hex');

    callback(null, buffer);
  }
};

if (typeof Uint8Array !== 'undefined' && typeof crypto !== 'undefined' && crypto.getRandomValues) {
  crypto_shim.randomBytes = function(n) {
    var array = new Uint8Array(n);
    crypto.getRandomValues(array);
    return new Buffer(String.fromCharCode.apply(String, array), 'binary');
  };
} else {
  crypto_shim.randomBytes = function(n) {
    var array = [];
    while (n--) array.push(Math.floor(Math.random() * 256));
    return new Buffer(array);
  };
}

crypto_shim.Cipher = function(cipherMode, key, iv) {
  this._mode = cipherMode;
  this._key  = CryptoJS.enc.Hex.parse(key.toString('hex'));
  this._iv   = CryptoJS.enc.Hex.parse(iv.toString('hex'));
  this._text = new Buffer([]);
};

crypto_shim.Cipher.prototype.update = function(chunk, inputEncoding, outputEncoding) {
  chunk = new Buffer(chunk, inputEncoding);
  this._text = Buffer.concat([this._text, chunk]);
  return '';
};

crypto_shim.Cipher.prototype.final = function(outputEncoding) {
  var message   = CryptoJS.enc.Hex.parse(this._text.toString('hex')),
      encrypted = CryptoJS.AES.encrypt(message, this._key, {iv: this._iv});

  encrypted = encrypted.toString(); // base64
  return new Buffer(encrypted, 'base64').toString(outputEncoding);
};

crypto_shim.Decipher = function(cipherMode, key, iv) {
  this._mode = cipherMode;
  this._key  = CryptoJS.enc.Hex.parse(key.toString('hex'));
  this._iv   = CryptoJS.enc.Hex.parse(iv.toString('hex'));
  this._text = new Buffer([]);
};

crypto_shim.Decipher.prototype.update = function(chunk, inputEncoding, outputEncoding) {
  chunk = new Buffer(chunk, inputEncoding);
  this._text = Buffer.concat([this._text, chunk]);
  return '';
};

crypto_shim.Decipher.prototype.final = function(outputEncoding) {
  var message = this._text.toString('base64'),
      plain   = CryptoJS.AES.decrypt(message, this._key, {iv: this._iv});

  plain = plain.toString(CryptoJS.enc.Hex);
  return new Buffer(plain, 'hex').toString(outputEncoding);
};

crypto_shim.Hmac = function(hashMode, key) {
  this._mode = hashMode;
  this._key  = CryptoJS.enc.Hex.parse(key.toString('hex'));
  this._text = new Buffer([]);
};

crypto_shim.Hmac.prototype.update = function(chunk, inputEncoding) {
  chunk = new Buffer(chunk, inputEncoding);
  this._text = Buffer.concat([this._text, chunk]);
  return this;
};

crypto_shim.Hmac.prototype.digest = function(outputEncoding) {
  var message = CryptoJS.enc.Hex.parse(this._text.toString('hex')),
      digest  = CryptoJS.HmacSHA256(message, this._key);

  digest = digest.toString(CryptoJS.enc.Hex);
  return new Buffer(digest, 'hex').toString(outputEncoding);
};

(function(factory) {
  if (typeof module === 'object' && typeof require === 'function')
    module.exports = factory(require('crypto'), Buffer, require('./buffer'));
  else if (typeof window !== 'undefined')
    window.Cipher = factory(crypto_shim, null, Buffer);

})(function(crypto, realBuffer, fakeBuffer) {
'use strict';

var pbkdf2 = function(password, salt, keylen, iterations, callback, context) {
  crypto.pbkdf2(password, salt, iterations, keylen, function(error, key) {
    if (typeof key === 'string') key = new Buffer(key, 'binary');
    callback.call(context, error, key);
  });
};

var Cipher = function(key, options) {
  options = options || {};

  if (key instanceof Array)
    this._keyPair = key;
  else
    this._key = key;

  this._format  = (options.format === undefined) ? Cipher.DEFAULT_FORMAT : options.format;
  this._input   = (options.input  === undefined) ? Cipher.DEFAULT_INPUT  : options.input;
  this._salt    = (options.salt   === undefined) ? Cipher.UUID           : options.salt;
  this._work    = (options.work   === undefined) ? Cipher.DEFAULT_WORK   : options.work;

  this._mode    = Cipher.DEFAULT_MODE;
  this._mac     = Cipher.DEFAULT_MAC;
  this._keySize = Cipher.KEY_SIZE;
  this._ivSize  = Cipher.BLOCK_SIZE;
  this._macSize = Cipher.MAC_SIZE;
};

Cipher.DEFAULT_WORK   = 1000;
Cipher.DEFAULT_MODE   = 'aes-256-cbc';
Cipher.DEFAULT_MAC    = 'sha256';
Cipher.DEFAULT_FORMAT = 'base64';
Cipher.DEFAULT_INPUT  = 'utf8';
Cipher.UUID           = '73e69e8a-cb05-4b50-9f42-59d76a511299';
Cipher.KEY_SIZE       = 32;
Cipher.BLOCK_SIZE     = 16;
Cipher.MAC_SIZE       = 32;

Cipher.concatBuffer = function(list) {
  if (list[0] instanceof fakeBuffer) return fakeBuffer.concat(list);
  if (realBuffer && realBuffer.concat) return realBuffer.concat(list);
  return fakeBuffer.concat(list, null, realBuffer);
};

Cipher.randomKeys = function() {
  var buffer     = crypto.randomBytes(2 * Cipher.KEY_SIZE),
      encryptKey = buffer.slice(0, Cipher.KEY_SIZE),
      signKey    = buffer.slice(Cipher.KEY_SIZE, buffer.length);

  return [encryptKey, signKey];
};

Cipher.prototype.deriveKeys = function(callback, context) {
  if (this._keyPair) return callback.apply(context, this._keyPair);
  var self = this;

  pbkdf2(this._key, this._salt, 2 * this._keySize, this._work, function(error, key) {
    var encryptKey = key.slice(0, self._keySize),
        signKey    = key.slice(self._keySize, key.length);

    self._keyPair = [encryptKey, signKey];
    callback.call(context, encryptKey, signKey);
  }, this);
};

Cipher.prototype.encrypt = function(plaintext, callback, context) {
  this.deriveKeys(function(encryptKey, signKey) {
    var iv         = crypto.randomBytes(this._ivSize),
        cipher     = crypto.createCipheriv(this._mode, encryptKey.toString('binary'), iv.toString('binary')),
        ciphertext = cipher.update(plaintext, this._input, 'binary') + cipher.final('binary');

    ciphertext = new Buffer(ciphertext, 'binary');

    var result = new Buffer(iv.length + ciphertext.length);
    iv.copy(result);
    ciphertext.copy(result, iv.length);

    var hmac = crypto.createHmac(this._mac, signKey.toString('binary'));
    hmac.update(result);
    hmac = new Buffer(hmac.digest('binary'), 'binary');

    var out = new Buffer(result.length + hmac.length);

    result.copy(out);
    hmac.copy(out, result.length);

    if (this._format) out = out.toString(this._format);
    callback.call(context, null, out);
  }, this);
};

Cipher.prototype.decrypt = function(ciphertext, callback, context) {
  this.deriveKeys(function(encryptKey, signKey) {
    try {
      var buffer    = new Buffer(ciphertext, this._format),
          message   = buffer.slice(0, Math.max(buffer.length - this._macSize, 0)),
          iv        = message.slice(0, Math.min(this._ivSize, message.length)),
          payload   = message.slice(Math.min(this._ivSize, message.length)),
          mac       = buffer.slice(Math.max(buffer.length - this._macSize, 0)),
          cipher    = crypto.createDecipheriv(this._mode, encryptKey.toString('binary'), iv.toString('binary')),
          plaintext = cipher.update(payload, 'binary', this._input) + cipher.final(this._input);
    }
    catch (error) {
      return callback.call(context, error);
    }

    var hmac = crypto.createHmac(this._mac, signKey.toString('binary'));
    hmac.update(message);
    hmac = new Buffer(hmac.digest('binary'), 'binary');

    var expected = crypto.createHmac(this._mac, this._salt).update(hmac).digest('hex'),
        actual   = crypto.createHmac(this._mac, this._salt).update(mac).digest('hex');

    if (expected !== actual)
      callback.call(context, new Error('DecryptError'));
    else if (plaintext === null)
      callback.call(context, new Error('DecryptError'));
    else
      callback.call(context, null, plaintext);
  }, this);
};

var c = new Cipher(Cipher.randomKeys(), {format: 'binary', input: 'binary'});
c.encrypt(new Buffer(2 * Cipher.KEY_SIZE), function(e, ciphertext) {
  Cipher.ENCRYPTED_KEYPAIR_SIZE = ciphertext.length;
});

return Cipher;
});

var keys = function(object) {
  var list = [];
  for (var key in object) {
    if (object.hasOwnProperty(key))
      list.push(key);
  }
  return list;
};

var map = function(list, mapper, context) {
  var result = [];
  for (var i = 0, n = list.length; i < n; i++) {
    result[i] = mapper.call(context, list[i], i, list);
  }
  return result;
};

var queryparse = function(string) {
  if (typeof string === 'object') return string;
  if (/^ *$/.test(string)) return {};

  var params = {},
      pairs  = string.split('&'),
      parts;

  for (var i = 0, n = pairs.length; i < n; i++) {
    parts = pairs[i].split('=');
    params[decodeURIComponent(parts[0])] = decodeURIComponent(parts.slice(1).join('='));
  }
  return params;
};

var querystring = function(object) {
  if (typeof object === 'string') return object;
  var pairs = [];
  for (var key in object) {
    pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(object[key]));
  }
  return pairs.join('&');
};

var request = function(method, url, params, headers, options, callback, context) {
  params = querystring(params);

  if (method === 'GET') {
    if (params !== '') url = url + (/\?/.test(url) ? '&' : '?') + params;
  }
  else if (method === 'PUT') {
    headers['Content-Length'] = params.length;
  }
  else if (method === 'DELETE') {
    headers['Content-Length'] = '0';
  }

  var xhr = window.XDomainRequest ? new XDomainRequest() : new XMLHttpRequest();

  xhr.open(method, url, true);
  for (var key in headers) {
    if (xhr.setRequestHeader) xhr.setRequestHeader(key, headers[key]);
  }

  xhr.onload = xhr.onerror = xhr.ontimeout = function() {
    if (xhr.status === 0)
      return callback.call(context, new Error('Request failied: ' + url));

    var headers = {},
        raw     = xhr.getAllResponseHeaders();

    map(raw.match(/^[^:]+:/gm) || [], function(name) {
      name = name.replace(/^\s*/, '').replace(/:\s*$/, '');
      headers[name.toLowerCase()] = xhr.getResponseHeader(name);
    });
    callback.call(context, null, {
      statusCode: xhr.status,
      headers:    headers,
      body:       xhr.responseText
    });
  };

  if (method === 'PUT') xhr.send(params);
  else xhr.send('');
};

var oauth = {
  authorize: function(target, clientId, scopes, options) {
    var sep = /\?/.test(target) ? '&' : '?';

    target = target + sep + querystring({
      client_id:      clientId,
      redirect_uri:   window.location.href.replace(/#.*$/, ''),
      scope:          scopes.join(' '),
      response_type:  'token',
      state:          options.state
    });
    window.location.href = target;
  }
};

var Vault = function(settings) {
  this._phrase   = settings.phrase || '';
  this._length   = settings.length || Vault.DEFAULT_LENGTH;
  this._repeat   = settings.repeat || Vault.DEFAULT_REPEAT;
  this._allowed  = Vault.ALL.slice();
  this._required = [];

  var types = Vault.TYPES, value;
  for (var i = 0, n = types.length; i < n; i++) {
    value = settings[types[i].toLowerCase()];
    if (value === 0) {
      this.subtract(Vault[types[i]]);
    } else if (typeof value === 'number') {
      this.require(Vault[types[i]], value);
    }
  }

  var n = this._length - this._required.length;
  while (n >= 0 && n--) this._required.push(this._allowed);
};

Vault.UUID = 'e87eb0f4-34cb-46b9-93ad-766c5ab063e7';
Vault.DEFAULT_LENGTH = 20;
Vault.DEFAULT_REPEAT = 0;

Vault.LOWER     = 'abcdefghijklmnopqrstuvwxyz'.split('');
Vault.UPPER     = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
Vault.ALPHA     = Vault.LOWER.concat(Vault.UPPER);
Vault.NUMBER    = '0123456789'.split('');
Vault.ALPHANUM  = Vault.ALPHA.concat(Vault.NUMBER);
Vault.SPACE     = [' '];
Vault.DASH      = ['-', '_'];
Vault.SYMBOL    = '!"#$%&\'()*+,./:;<=>?@[\\]^{|}~'.split('').concat(Vault.DASH);
Vault.ALL       = Vault.ALPHANUM.concat(Vault.SPACE).concat(Vault.SYMBOL);

Vault.TYPES = 'LOWER UPPER NUMBER SPACE DASH SYMBOL'.split(' ');

Vault.extend = function(target, source) {
  for (var key in source) {
    if (!target.hasOwnProperty(key))
      target[key] = source[key];
  }
  return target;
};

Vault.createHash = function(key, message, entropy) {
  var CJS   = (typeof CryptoJS !== 'undefined') ? CryptoJS : require('vault-cipher/lib/crypto-js'),
      bytes = (entropy || 256) / 8;

  return CJS.PBKDF2(key, message, {keySize: Math.ceil(bytes / 4), iterations: 8}).toString();
};

Vault.indexOf = function(list, item) {
  if (list.indexOf) return list.indexOf(item);
  for (var i = 0, n = list.length; i < n; i++) {
    if (list[i] === item) return i;
  }
  return -1;
};

Vault.map = function(list, callback, context) {
  if (list.map) return list.map(callback, context);
  var result = [];
  for (var i = 0, n = list.length; i < n; i++)
    result.push(callback.call(context, list[i]));
  return result;
};

Vault.toBits = function(digit) {
  var string = parseInt(digit, 16).toString(2);
  while (string.length < 4) string = '0' + string;
  return string;
};

Vault.prototype.subtract = function(charset, allowed) {
  if (!charset) return;
  allowed = allowed || this._allowed;
  for (var i = 0, n = charset.length; i < n; i++) {
    var index = Vault.indexOf(allowed, charset[i]);
    if (index >= 0) allowed.splice(index, 1);
  }
  return allowed;
};

Vault.prototype.require = function(charset, n) {
  if (!charset) return;
  while (n--) this._required.push(charset);
};

Vault.prototype.entropy = function() {
  var entropy = 0;
  for (var i = 0, n = this._required.length; i < n; i++) {
    entropy += Math.ceil(Math.log(i+1) / Math.log(2));
    entropy += Math.ceil(Math.log(this._required[i].length) / Math.log(2));
  }
  return entropy;
};

Vault.prototype.generate = function(service) {
  if (this._required.length > this._length)
    throw new Error('Length too small to fit all required characters');

  if (this._allowed.length === 0)
    throw new Error('No characters available to create a password');

  var required = this._required.slice(),
      stream   = new Vault.Stream(this._phrase, service, this.entropy()),
      result   = '',
      index, charset, previous, i, same;

  while (result.length < this._length) {
    index    = stream.generate(required.length);
    charset  = required.splice(index, 1)[0];
    previous = result.charAt(result.length - 1);
    i        = this._repeat - 1;
    same     = previous && (i >= 0);

    while (same && i--)
      same = same && result.charAt(result.length + i - this._repeat) === previous;
    if (same)
      charset = this.subtract([previous], charset.slice());

    index   = stream.generate(charset.length);
    result += charset[index];
  }

  return result;
};


// Generate uniformly distributed output in any base from a bit stream
// http://checkmyworking.com/2012/06/converting-a-stream-of-binary-digits-to-a-stream-of-base-n-digits/

Vault.Stream = function(phrase, service, entropy) {
  this._phrase  = phrase;
  this._service = service;

  var hash = Vault.createHash(phrase, service + Vault.UUID, 2 * entropy),
      bits = Vault.map(hash.split(''), Vault.toBits).join('').split('');

  this._bases = {
    '2': Vault.map(bits, function(s) { return parseInt(s, 2) })
  };
};

Vault.Stream.prototype.generate = function(n, base, inner) {
  base = base || 2;

  var value = n,
      k = Math.ceil(Math.log(n) / Math.log(base)),
      r = Math.pow(base, k) - n,
      chunk;

  loop: while (value >= n) {
    chunk = this._shift(base, k);
    if (!chunk) return inner ? n : null;

    value = this._evaluate(chunk, base);

    if (value >= n) {
      if (r === 1) continue loop;
      this._push(r, value - n);
      value = this.generate(n, r, true);
    }
  }
  return value;
};

Vault.Stream.prototype._evaluate = function(chunk, base) {
  var sum = 0,
      i   = chunk.length;

  while (i--) sum += chunk[i] * Math.pow(base, chunk.length - (i+1));
  return sum;
};

Vault.Stream.prototype._push = function(base, value) {
  this._bases[base] = this._bases[base] || [];
  this._bases[base].push(value);
};

Vault.Stream.prototype._shift = function(base, k) {
  var list = this._bases[base];
  if (!list || list.length < k) return null;
  else return list.splice(0,k);
};


if (typeof module === 'object')
  module.exports = Vault;

(function(factory) {
  var isNode = (typeof require === 'function'),

      async  = isNode ? require('async')        : window.async,
      crypto = isNode ? require('crypto')       : window.crypto_shim,
      Cipher = isNode ? require('vault-cipher') : window.Cipher,
      Vault  = isNode ? require('./vault')      : window.Vault,

      Loader = factory(async, crypto, Cipher, Vault);

  if (isNode)
    module.exports = Loader;
  else
    Vault.Loader = Loader;

})(function(async, crypto, Cipher, Vault) {

var sort = function(object) {
  if (typeof object !== 'object') return object;
  if (object === null) return null;

  if (object instanceof Array)
    return object.map(function(o) { return sort(o) })

  var copy = {}, keys = Object.keys(object).sort();
  for (var i = 0, n = keys.length; i < n; i++)
    copy[keys[i]] = sort(object[keys[i]]);

  return copy;
};

var Loader = function(adapter, key, options) {
  this._adapter = adapter;
  this._cipher  = new Cipher(key, {format: 'binary', input: 'binary', salt: Vault.UUID, work: 100});
  this._cache   = (options.cache !== false) ? {} : null;
  this._queues  = {};
};

Loader.BUCKETS = '0123456789abcdef'.split('');
Loader.LOCAL   = 'local';

Loader.prototype.getName = function() {
  return this._adapter.getName();
};

Loader.prototype.pathForService = function(service, callback, context) {
  if (!service)
    return callback.call(context, new Error('No service name given'));

  this._cipher.deriveKeys(function(encryptionKey, signingKey) {
    var hmac = crypto.createHmac('sha256', signingKey);
    hmac.update(service);
    callback.call(context, null, 'services/' + hmac.digest('hex')[0]);
  }, this);
};

Loader.prototype.load = function(pathname, callback, context) {
  if (this._cache && this._cache[pathname])
    return callback.call(context, null, this._cache[pathname]);

  this._adapter.load(pathname, function(error, content) {
    if (error) return callback.call(context, error);
    if (!content) return callback.call(context, null, {});

    content = new Buffer(content, 'base64');

    var err      = new Error('Your .vault database is unreadable; check your VAULT_KEY and VAULT_PATH settings'),
        size     = Cipher.KEY_SIZE,
        encSize  = Cipher.ENCRYPTED_KEYPAIR_SIZE;

    if (content.length < encSize) return callback.call(context, err);

    var keyBlock = content.slice(0, encSize),
        payload  = content.slice(encSize, content.length);

    this._cipher.decrypt(keyBlock, function(error, keyBlock) {
      if (error) return callback.call(context, err);

      keyBlock = new Buffer(keyBlock, 'binary');

      var keys   = [keyBlock.slice(0, size), keyBlock.slice(size, 2 * size)];
          cipher = new Cipher(keys, {format: 'binary'});

      cipher.decrypt(payload, function(error, plaintext) {
        if (error) return callback.call(context, err);

        try { config = JSON.parse(plaintext) }
        catch (e) { return callback.call(context, err) }

        if (this._cache) this._cache[pathname] = config;
        callback.call(context, null, config);
      }, this);
    }, this);
  }, this);
};

Loader.prototype.dump = function(pathname, config, callback, context) {
  config = sort(config);
  if (this._cache) this._cache[pathname] = config;

  var json     = JSON.stringify(config, true, 2),
      keys     = Cipher.randomKeys(),
      keyBlock = Cipher.concatBuffer(keys),
      cipher   = new Cipher(keys, {format: 'binary'});

  this._enqueue(pathname, function(done) {
    cipher.encrypt(json, function(error, ciphertext) {
      this._cipher.encrypt(keyBlock, function(error, keyBlock) {
        ciphertext = new Buffer(ciphertext, 'binary');
        keyBlock   = new Buffer(keyBlock, 'binary');

        var wrapper = Cipher.concatBuffer([keyBlock, ciphertext]);

        this._adapter.dump(pathname, wrapper.toString('base64'), function(error) {
          callback.call(context, error);
          done(error);
        });
      }, this);
    }, this);
  });
};

Loader.prototype.remove = function(pathname, callback, context) {
  this._enqueue(pathname, function(done) {
    this._adapter.remove(pathname, function(error) {
      callback.call(context, error);
      done(error);
    });
  });
};

Loader.prototype._enqueue = function(pathname, task) {
  var q    = this._queues,
      self = this;

  q[pathname] = q[pathname] || async.queue(function(task, cb) { task.call(self, cb) }, 1);
  q[pathname].push(task);
};

Loader.sort = sort;
return Loader;
});

var $ = function(id) { return document.getElementById(id) };

var on = function(element, event, listener) {
  if (!element) return;
  if (element.addEventListener)
    element.addEventListener(event, listener, false);
  else
    element.attachEvent('on' + event, listener);
};

var getRadio = function(name) {
  var inputs = document.getElementsByTagName('input'), input;
  for (var i = 0, n = inputs.length; i < n; i++) {
    input = inputs[i];
    if (input.type === 'radio' && input.name === name && input.checked)
      return input.value;
  }
};

var setRadio = function(name, value) {
  var inputs = document.getElementsByTagName('input'), input;
  for (var i = 0, n = inputs.length; i < n; i++) {
    input = inputs[i];
    if (input.type === 'radio' && input.name === name) {
      switch (input.value) {
        case 'required':
          input.checked = (value && value > 0);
          break;
        case 'allowed':
          input.checked = (value === undefined);
          break;
        case 'forbidden':
          input.checked = (value === 0);
          break;
      }
    }
  }
};

var togglePassword = function(id) {
  var field    = $(id),
      text     = $(id + '-text'),
      checkbox = $('show-' + id);

  if (text) text.style.display = 'none';

  on(checkbox, 'click', function() {
    if (checkbox.checked) {
      field.style.display = 'none';
      text.style.display  = '';
    } else {
      field.style.display = '';
      text.style.display  = 'none';
    }
  });

  on(field, 'keyup', function() { text.value = field.value });
  on(text, 'keyup', function() { field.value = text.value });
};
togglePassword('passphrase');

(function() {
  var message  = $('message'),
      service  = $('service'),
      phrase   = $('passphrase'),
      required = $('required'),
      length   = $('vlength'),
      repeat   = $('repeat'),
      word     = $('word'),
      wordText = $('word-text'),
      TYPES    = 'lower upper number dash space symbol'.split(' ');

  //if (service) service.focus();
  if (phrase) phrase.focus();

  var getSettings = function() {
    if (!length) return null;

    var plength   = parseInt(length.value, 10),
        prepeat   = parseInt(repeat.value, 10),
        rlength   = parseInt(required.value, 10),
        settings  = {phrase: phrase.value, length: plength, repeat: prepeat},
        value;

    for (var i = 0, n = TYPES.length; i < n; i++) {
      value = getRadio(TYPES[i]);
      if (value === 'forbidden')
        settings[TYPES[i]] = 0;
      else if (value === 'required')
        settings[TYPES[i]] = rlength;
    }

    return settings;
  };
  var defaultSettings = getSettings();

  var update = function() {
    var settings = getSettings();
    if (!settings) return;
    try {
      if (service.value && phrase.value) {
        word.value = new Vault(settings).generate(service.value);
      } else {
        word.value = '';
      }
    } catch (e) {
      word.value = '!! ' + e.message;
    }
  };

  var inputs = document.getElementsByTagName('input');
  for (var i = 0, n = inputs.length; i < n; i++) {
    if (inputs[i].id === 'word' || inputs[i].type === 'checkbox') continue;
    on(inputs[i], 'keyup', update);
    on(inputs[i], 'change', update);
  }

//  var fetchSettings = function() {
//    if (!store) return;
//
//    message.innerHTML = 'Loading&hellip;';
//    message.className = 'active';
//
//    store.serviceSettings(service.value, true, function(error, settings) {
//      if (error)
//        return message.innerHTML = 'Error';
//
//      phrase.value = settings.phrase || defaultSettings.phrase;
//      length.value = settings.length || defaultSettings.length;
//      repeat.value = settings.repeat || defaultSettings.repeat || '';
//
//      var value, req, i, n = TYPES.length;
//
//      for (i = 0; i < n; i++) {
//        value = settings[TYPES[i]];
//        req = req || value;
//        setRadio(TYPES[i], value);
//      }
//      required.value = (req === undefined) ? 2 : req;
//      update();
//      message.innerHTML = store.getName();
//      message.className = '';
//    });
//  };
//  on(service, 'blur', fetchSettings);

//  var insert = function() {
//    var password = word.value.replace(/'/g, '\\\'');
//    chrome.tabs.executeScript(null, {
//      code: "(document.activeElement||{}).value = '" + password + "';"
//    });
//    window.close();
//  };
//  var insertPassword = $('insert-password');
//  on(insertPassword, 'click', function(e) {
//    e.preventDefault();
//    insert();
//  });
//  on(service, 'keydown', function(e) {
//    if (e.keyCode === 13) insert();
//  });
//  on(phrase, 'keydown', function(e) {
//    if (e.keyCode === 13) insert();
//  });
})();

(function() {
  var connectForm   = $('connectForm'),
      connectResult = $('connectResult'),
      address       = $('address'),
      key           = $('key'),
      feedback      = $('feedback'),
      userDisplay   = $('userId'),
      bookmarkLink  = $('bookmark');

  // TODO check that storage will work in this browser

  var hash      = location.hash.replace(/^#/, ''),
      query     = location.search.replace(/^\?/, ''),
      payload   = hash || query,
      params    = queryparse(payload),
      token     = params.access_token,
      error     = params.error,
      state     = params.state || '',
      keyPair   = localStorage.keyPair,
      size      = Cipher.KEY_SIZE,
      userId    = params.address || state.split(':').slice(1).join(':'),
      masterKey = params.key,
      cipher,
      keys;

  localStorage.clear();

  if (token) {
    if (masterKey) {
      window.store = new Vault.Store(new Vault.RSAdapter(userId, {token: token}), masterKey, {});
      $('message').innerHTML = userId;
    } else {
      masterKey = state.split(':')[0];
      keyPair   = new Buffer(keyPair, 'base64');
      keys      = [keyPair.slice(0, size), keyPair.slice(size, 2 * size)];
      cipher    = new Cipher(keys, {format: 'hex'});

      cipher.decrypt(masterKey, function(error, masterKey) {
        if (error) return feedback.innerHTML = error.message;

        var params   = {access_token: token, address: userId, key: masterKey},
            bookmark = location.protocol + '//' + location.host + '/#' + querystring(params);

        if (!connectForm) return;
        connectForm.style.display = 'none';
        userDisplay.innerHTML = userId;
        bookmarkLink.href = bookmark;
      });
    }
  } else {
    if (error && connectForm) {
      address.value = userId;
      feedback.innerHTML = 'Could not make a connection to ' + userId;
    }
    if (connectResult)
      connectResult.style.display = 'none';
  }

  var connect = function(userId, masterKey) {
    var keys   = Cipher.randomKeys(),
        cipher = new Cipher(keys, {format: 'hex'});

    localStorage.keyPair = Buffer.concat(keys).toString('base64');

    cipher.encrypt(masterKey, function(error, keys) {
      var remote = new Vault.RSAdapter(userId, {state: keys + ':' + userId});
      feedback.innerHTML = 'Connecting&hellip;';
      remote.authorize(function(error) { feedback.innerHTML = error.message });
    });
  };

  on(connectForm, 'submit', function(e) {
    if (e.preventDefault) e.preventDefault();
    else e.returnValue = false;
    connect(address.value, key.value); // TODO error is key is blank
  });
})();

var wordFocused = false;
on(word, 'focus', function(e) {
  wordFocused = true;
});
on(word, 'blur', function(e) {
  wordFocused = false;
});
on(word, 'mouseup', function(e) {
  if (wordFocused) word.setSelectionRange(0, word.value.length);
});
