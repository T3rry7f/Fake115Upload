// Test by @T3rry

var forge = require('node-forge');
var urlencode = require('urlencode');
var http = require('http');

var pub_key='-----BEGIN PUBLIC KEY-----\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr\
PmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR\
IVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo\
kFiz4uPxhrB7BGqZbQIDAQAB\
-----END PUBLIC KEY-----'

var private_key='-----BEGIN RSA PRIVATE KEY-----\
MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC\
TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6\
FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB\
AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/\
3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t\
viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy\
A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q\
pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z\
DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft\
5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN\
4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo\
YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v\
wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=\
-----END RSA PRIVATE KEY-----'

var rsa = forge.pki.rsa;
const priv = forge.pki.privateKeyFromPem(private_key);
const pub = forge.pki.publicKeyFromPem(pub_key);
const g_key_l=[0x42,0xda,0x13,0xba,0x78,0x76,0x8d,0x37,0xe8,0xee,0x04,0x91]
const g_key_s=[0x29,0x23,0x21,0x5e]
const g_kts=[0xf0,0xe5,0x69,0xae,0xbf,0xdc,0xbf,0x5a,0x1a,0x45,0xe8,0xbe,0x7d,0xa6,0x73,0x88,0xde,0x8f,0xe7,0xc4,0x45,0xda,0x86,0x94,0x9b,0x69,0x92,0x0b,0x6a,0xb8,0xf1,0x7a,0x38,0x06,0x3c,0x95,0x26,0x6d,0x2c,0x56,0x00,0x70,0x56,0x9c,0x36,0x38,0x62,0x76,0x2f,0x9b,0x5f,0x0f,0xf2,0xfe,0xfd,0x2d,0x70,0x9c,0x86,0x44,0x8f,0x3d,0x14,0x27,0x71,0x93,0x8a,0xe4,0x0e,0xc1,0x48,0xae,0xdc,0x34,0x7f,0xcf,0xfe,0xb2,0x7f,0xf6,0x55,0x9a,0x46,0xc8,0xeb,0x37,0x77,0xa4,0xe0,0x6b,0x72,0x93,0x7e,0x51,0xcb,0xf1,0x37,0xef,0xad,0x2a,0xde,0xee,0xf9,0xc9,0x39,0x6b,0x32,0xa1,0xba,0x35,0xb1,0xb8,0xbe,0xda,0x78,0x73,0xf8,0x20,0xd5,0x27,0x04,0x5a,0x6f,0xfd,0x5e,0x72,0x39,0xcf,0x3b,0x9c,0x2b,0x57,0x5c,0xf9,0x7c,0x4b,0x7b,0xd2,0x12,0x66,0xcc,0x77,0x09,0xa6]

m115_l_rnd_key=[]
m115_s_rnd_key=[]
key_s=[]
key_l=[]

function intToByte(i) {
        var b = i & 0xFF;
        var c = 0;
        if (b >= 256) {
            c = b % 256;
            c = -1 * (256 - c);
        } else {
            c = b;
        }

        return c

    }

function stringToArray(s) {

	var map = Array.prototype.map

    var array = map.call(s,function(x){
    return x.charCodeAt(0);

	})

	return array
  }

function arrayTostring(array){
	var result = "";
	for(var i = 0; i < array.length; ++i){
		result+= (String.fromCharCode(array[i]));
	}
	return result;
}


function dump(s){

	var ss=''
	for (var i = 0; i <s.length; i++) {
		ss+=(s[i].toString(16))
	}
    console.log(ss)

}

function m115_xorinit(randkey,sk_len)
{
	var	length=sk_len *(sk_len-1)
	var	index=0
	var	xorkey=''

		if (randkey)
		{
			for (var i = 0; i <sk_len; i++) {
				x  =  intToByte((randkey[i]) + (g_kts[index]))
				xorkey += String.fromCharCode(g_kts[length]^ x)
				length -=sk_len
				index +=sk_len
			}	
		if(sk_len==4)
		{
			key_s=stringToArray(xorkey)
		}
		else if(sk_len==12)
		{
			
			key_l=stringToArray(xorkey)
		}

	}
}
function xor115_enc(src,key){

    var  lkey=key.length
    var  secret=[]
    var  num=0

    var  pad= (src.length)%4

		if (pad >0){

			for (var i = 0; i <pad; i++) {

				secret.push((src[i])^key[i])
			}
				
			src=src.slice(pad)
		}
			
        for (var i = 0; i<src.length; i++) {
        	if (num>=lkey){

        		num=num%lkey
        	}
        	
        	secret.push((src[i]^key[num]))
        	num+=1
        }

        return secret


}
function genRandom(len)
{

  var keys=[]
  var chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz23456789';    
　var maxPos = chars.length;
　　
　　for (i = 0; i < len; i++) {
　　　　keys.push(chars.charAt(Math.floor(Math.random() * maxPos)).charCodeAt(0));
　　}
　　return keys;
}
function m115_encode(plaintext)
{
       console.log('m115_encode:')
       
       key_l=g_key_l

       m115_l_rnd_key=genRandom(16)

       m115_xorinit(m115_l_rnd_key,4)

       var tmp=xor115_enc(stringToArray(plaintext),key_s).reverse()

       var xortext= xor115_enc(tmp,key_l)
       
       var text=arrayTostring(m115_l_rnd_key)+arrayTostring(xortext)

       var ciphertext =pub.encrypt(text)

       ciphertext=urlencode(forge.util.encode64(ciphertext))

       return ciphertext

    }

function  m115_decode(ciphertext)
{
	console.log('m115_decode:')
	var bciphertext=forge.util.decode64(ciphertext)
	var block=bciphertext.length/(128)
	var plaintext =''

	var index=0

	for (var i = 1; i <=block; ++i) {
		plaintext+=priv.decrypt(bciphertext.slice(index, i*128))
		index+=128
	}
	
    m115_s_rnd_key =stringToArray(plaintext.slice(0,16))

	plaintext=plaintext.slice(16);

	m115_xorinit(m115_l_rnd_key,4)

	m115_xorinit(m115_s_rnd_key,12)

	tmp=xor115_enc(stringToArray(plaintext),key_l).reverse()

	plaintext=xor115_enc(tmp,key_s)

	return arrayTostring(plaintext)
}


function test()
{

var post_data = 'data='+m115_encode('{"pickcode":"xxxxxxxxxxxxxxxxxxxxxxx"}')
var options = {
host: 'proapi.115.com',
port: 80,
path: '/app/chrome/downurl',
method: 'post',
headers: {
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36 115Browser/23.9.2',
'Content-Type':'application/x-www-form-urlencoded',
'Content-Length':post_data.length,
'Cookie': 'xxxxxxxxxxxxxxxxxxxxxxxxx'
}};

  var post_req = http.request(options, function(res) {
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
          var bodyString = JSON.parse(chunk)['data'];
          resp=m115_decode(bodyString)          
          console.log(JSON.parse(resp))
      });
  });

  post_req.write(post_data);
  post_req.end();

}

test()
