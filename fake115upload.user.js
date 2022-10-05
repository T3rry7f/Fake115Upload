// ==UserScript==
// @author       T3rry
// @name         115Link Helper
// @description  115文件备份导入
// @namespace    https://github.com/T3rry7f/Fake115Upload
// @version      1.4.5
// @match        https://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @connect      proapi.115.com
// @connect      webapi.115.com
// @connect      115.com
// @require      https://cdn.bootcss.com/jsSHA/2.3.1/sha1.js
// @require      https://greasyfork.org/scripts/5392-waitforkeyelements/code/WaitForKeyElements.js?version=115012
// @require      https://gist.githubusercontent.com/BrockA/2625891/raw/9c97aa67ff9c5d56be34a55ad6c18a314e5eb548/waitForKeyElements.js
// @require      https://cdn.jsdelivr.net/npm/node-forge@0.10.0/dist/forge.min.js
// @downloadURL none
// ==/UserScript==
(function() {
    'use strict';

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

    const priv = forge.pki.privateKeyFromPem(private_key);
    const pub = forge.pki.publicKeyFromPem(pub_key);
    const g_key_l=[0x42,0xda,0x13,0xba,0x78,0x76,0x8d,0x37,0xe8,0xee,0x04,0x91]
    const g_key_s=[0x29,0x23,0x21,0x5e]
    const g_kts=[0xf0,0xe5,0x69,0xae,0xbf,0xdc,0xbf,0x5a,0x1a,0x45,0xe8,0xbe,0x7d,0xa6,0x73,0x88,0xde,0x8f,0xe7,0xc4,0x45,0xda,0x86,0x94,0x9b,0x69,0x92,0x0b,0x6a,0xb8,0xf1,0x7a,0x38,0x06,0x3c,0x95,0x26,0x6d,0x2c,0x56,0x00,0x70,0x56,0x9c,0x36,0x38,0x62,0x76,0x2f,0x9b,0x5f,0x0f,0xf2,0xfe,0xfd,0x2d,0x70,0x9c,0x86,0x44,0x8f,0x3d,0x14,0x27,0x71,0x93,0x8a,0xe4,0x0e,0xc1,0x48,0xae,0xdc,0x34,0x7f,0xcf,0xfe,0xb2,0x7f,0xf6,0x55,0x9a,0x46,0xc8,0xeb,0x37,0x77,0xa4,0xe0,0x6b,0x72,0x93,0x7e,0x51,0xcb,0xf1,0x37,0xef,0xad,0x2a,0xde,0xee,0xf9,0xc9,0x39,0x6b,0x32,0xa1,0xba,0x35,0xb1,0xb8,0xbe,0xda,0x78,0x73,0xf8,0x20,0xd5,0x27,0x04,0x5a,0x6f,0xfd,0x5e,0x72,0x39,0xcf,0x3b,0x9c,0x2b,0x57,0x5c,0xf9,0x7c,0x4b,0x7b,0xd2,0x12,0x66,0xcc,0x77,0x09,0xa6]
    var m115_l_rnd_key= genRandom(16)
    var m115_s_rnd_key=[]
    var key_s=[]
    var key_l=[]
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
    function m115_init()
    {
        key_s=[]
        key_l=[]
    }
    function m115_setkey(randkey,sk_len)
    {
        var length=sk_len *(sk_len-1)
        var index=0
        var xorkey=''
        if (randkey)
        {
            for (var i = 0; i <sk_len; i++) {
                var x  =  intToByte((randkey[i]) + (g_kts[index]))
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
            for (var i = 0; i <pad; i++)
            {
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
        for (var i = 0; i < len; i++) {
            keys.push(chars.charAt(Math.floor(Math.random() * maxPos)).charCodeAt(0));
        }
        return keys;
    }
    function m115_encode(plaintext)
    {
        console.log('m115_encode:')
        m115_init()
        key_l=g_key_l
        m115_setkey(m115_l_rnd_key,4)
        var tmp=xor115_enc(stringToArray(plaintext),key_s).reverse()
        var xortext= xor115_enc(tmp,key_l)
        var text=arrayTostring(m115_l_rnd_key)+arrayTostring(xortext)
        var ciphertext =pub.encrypt(text)
        ciphertext=encodeURIComponent(forge.util.encode64(ciphertext))
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
        m115_setkey(m115_l_rnd_key,4)
        m115_setkey(m115_s_rnd_key,12)
        var tmp=xor115_enc(stringToArray(plaintext),key_l).reverse()
        plaintext=xor115_enc(tmp,key_s)
        return arrayTostring(plaintext)
    }
    var str=document.URL;
    var hProtocol="115://";
    var StoreFolder="导入";
    window.CID=0;
    waitForKeyElements("div.file-opr", AddCreateHashLinkBtn);
    waitForKeyElements("div.dialog-bottom", AddDownloadSha1Btn);
    var style = document.createElement("style");
    style.type = "text/css";
    var text = document.createTextNode("*{margin:0;padding:0;}  .pp_align{font-size: 12px;line-height:30px;font-weight: 500;text-align:center;border:1px solid #D1D4D6} .pub_switch_box{font-size: 0;display: inline-block;} .pub_switch { display: none;} .pub_switch + label {display: inline-block;position: relative;width: 56px;height: 32px;background-color: #fafbfa;border-radius: 50px;-webkit-transition: all 0.1s ease-in;transition: all 0.1s ease-in;} .pub_switch  + label:after {content: ' ';position: absolute;top: 0;width: 100%;height: 100%;-webkit-transition: box-shadow 0.1s ease-in;transition: box-shadow 0.1s ease-in;left: 0;border-radius: 100px;box-shadow: inset 0 0 0 0 #eee, 0 0 1px rgba(0,0,0,0.4);} .pub_switch  + label:before {content: ' ';position: absolute;top: 0px;left: 1px;z-index: 999999;width: 32px;height:32px;-webkit-transition: all 0.1s ease-in;transition: all 0.1s ease-in;border-radius: 100px;box-shadow: 0 3px 1px rgba(0,0,0,0.05), 0 0px 1px rgba(0,0,0,0.3);background: white;} .pub_switch:active + label:after {box-shadow: inset 0 0 0 20px #eee, 0 0 1px #eee;} .pub_switch:active + label:before {width: 37px;} .pub_switch:checked:active + label:before {width: 37px;left: 20px;} .pub_switch  + label:active {box-shadow: 0 1px 2px rgba(0,0,0,0.05), inset 0px 1px 3px rgba(0,0,0,0.1);} .pub_switch:checked + label:before {content: ' ';position: absolute;left: 31px;border-radius: 100px;} .pub_switch:checked + label:after {content: ' ';font-size: 1.5em;position: absolute;background: #2777F8;box-shadow: 0 0 1px #2777F8;}");
    style.appendChild(text);
    var head = document.getElementsByTagName("head")[0];
    head.appendChild(style);
    window.linkText=""
    window.reqcount=0
    window.cookie=document.cookie
    function delay(ms) {
        if(ms==0)
        {
            ms=1000*(Math.floor(Math.random()*(11-4))+4);
            console.log(ms);
        }
        return new Promise(resolve => setTimeout(resolve, ms))
    }
    function download(filename,content,contentType) {
        if (!contentType) contentType = 'application/octet-stream';
        var a = document.createElement('a');
        var blob = new Blob([content], { 'type': contentType });
        a.href = window.URL.createObjectURL(blob);
        a.download = filename;
        a.click();
    }
    function SetListView()
    {
        GM_xmlhttpRequest({
            method: "POST",
            url: 'https://115.com/?ct=user_setting&ac=set',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: PostData({
                setting:'{"view_file":"list"}'
            }),
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                }
            }
        });
    }
    function AddAutoPickUpBox()
    {
        var i=document.getElementById('js_top_panel_box');
        if (i!=null){
            var id=document.createElement('div');
            id.setAttribute('class','pub_switch_box');
            var ia=document.createElement('span');
            ia.innerText='自动提取:';
            ia.setAttribute('class','pp_align');
            var ip=document.createElement('input');
            ip.setAttribute('type','checkbox');
            ip.setAttribute('id','autopick');
            ip.setAttribute('class','pub_switch');
            var il=document.createElement('label');
            il.setAttribute('for','autopick');
            id.appendChild(ip);
            id.appendChild(il);
            i.appendChild(ia);
            i.appendChild(id);
        }
    }
    function AddStroeFloder()
    {
        GM_xmlhttpRequest({
            method: "POST",
            url: 'https://webapi.115.com/files/add',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            ,
            data: PostData({
                pid:'0',
                cname:StoreFolder
            }),
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                }
            }
        });
    }
    function Init()
    {
        //AddAutoPickUpBox();
        var cid=0;
        var info='';
        GM_xmlhttpRequest({
            method: "GET",
            url: 'https://aps.115.com/natsort/files.php?aid=1&cid=0&o=file_name&asc=1&offset=0&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&fc_mix=0&type=&star=&is_q=&is_share=',
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                    info = response.response;
                    try
                    {
                        info.data.forEach(function (line) {
                            if(line.n==StoreFolder)
                            {
                                window.CID=line.cid;
                            }
                        }                                         )
                        if(window.CID==0)
                        {
                            AddStroeFloder();
                        }
                    }
                    catch(err)
                    {
                        // alert(err);
                    }
                }
            }
        });
    }
    Init();
    function PostData(dict) {
        var k, tmp, v;
        tmp = [];
        for (k in dict) {
            v = dict[k];
            tmp.push(k + "=" + v);
        }
        console.log(tmp.join('&'))
        return tmp.join('&');
    };
    function UrlData(dict) {
        var k, tmp, v;
        tmp = [];
        for (k in dict) {
            v = dict[k];
            tmp.push((encodeURIComponent(k)) + "=" + (encodeURIComponent(v)));
        }
        return tmp.join('&');
    };
    function GetSig(userid, fileid, target, userkey) {
        var sha1, tmp;
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userid + fileid + fileid+target + "0");
        tmp = sha1.getHash('HEX');
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userkey + tmp + "000000");
        return sha1.getHash('HEX', {
            outputUpper: true
        });
    }
    async  function test(info,flag)
    {
        window.linkText=""
        if(info[0].indexOf('|')==-1 ){
            GetFilesByCID(info[0]);
            await delay(3000);
            while(window.reqcount!=0)
            {
                await delay(50);
            }
            download(info[1]+"_sha1.txt",window.linkText);
            return;
        }
        GetFileLink(info,flag);
    }
    function DeleteCookie(resp)
    {
        try
        {
            var reg =/set-cookie: .+;/g;
            var setcookie=reg.exec(resp)[0].split(';');
            var filecookie=setcookie[0].slice(11)+"; expires=Thu, 01 Jan 1970 00:00:00 UTC;"+setcookie[3]+";domain=.115.com";
            document.cookie =filecookie;
            RenewCookie()
            return filecookie;
        }
        catch(err)
        {
            return null;
        }
    }
    function RenewCookie()
    {
        var arryCookie=window.cookie.split(';');
        arryCookie.forEach(function (kv) {
            document.cookie=kv+";expires=Thu, 01 Jan 2100 00:00:00 UTC;;domain=.115.com"
        }
                          )
    }
    function GetFilesByCID(cid)
    {
        GM_xmlhttpRequest({
            method: "GET",
            url: "https://webapi.115.com/files?aid=1&cid="+cid+"&o=user_ptime&asc=0&offset=0&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&type=&star=&is_share=&suffix=&custom_order=&fc_mix=",
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                    var info = response.response;
                    try
                    {
                        info.data.forEach(function (line) {
                            if(line.cid!=cid) //folder
                            {
                                GetFilesByCID(line.cid);
                            }
                            else
                            {
                                GetFileLink([line.n+'|'+line.s+'|'+line.sha, line.pc,line.fid],false);
                            }
                        }
                                         )
                    }
                    catch(err)
                    {
                        GM_xmlhttpRequest({
                            method: "GET",
                            url: "https://aps.115.com/natsort/files.php?aid=1&cid="+cid+"&o=file_name&asc=1&offset=0&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&type=&star=&is_share=&suffix=&custom_order=&fc_mix=0",       responseType: 'json',
                            onload: function(response) {
                                if (response.status === 200) {
                                    var info = response.response;
                                    try
                                    {
                                        info.data.forEach(function (line) {
                                            if(line.cid!=cid) //folder
                                            {
                                                GetFilesByCID(line.cid);
                                            }
                                            else
                                            {
                                                GetFileLink([line.n+'|'+line.s+'|'+line.sha,line.pc,line.fid],false);
                                            }
                                        }
                                                         )
                                    }
                                    catch(err)
                                    {
                                        alert(err);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
    }
    function CreateHashLink(url,info,cookie,flag){

        var pre_buff=null;
        if(url!==undefined){
            GM_xmlhttpRequest({
                method: "GET",
                url: url,
                headers: {
                    "Range": "bytes=0-154112",
                    "Cookie": cookie
                },
                responseType: 'arraybuffer',
                onload: function(response,shalink) {
                    if (response.status === 206) {
                        window.reqcount-=1
                        pre_buff = response.response;
                        try
                        {
                            var data= new Uint8Array(pre_buff);
                            var sha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
                            sha1.update(data.slice(0, 128 * 1024));
                            var preid = sha1.getHash('HEX', {
                                outputUpper: true
                            });
                            console.log(hProtocol+info[0]+'|'+preid);
                            window.linkText+=hProtocol+info[0]+'|'+preid+'\n'
                            if(flag){
                                var link= prompt("复制链接到剪贴板",hProtocol+info[0]+'|'+preid);
                            }
                        }
                        catch(err)
                        {
                            alert(err);
                        }
                    } else {
                        window.reqcount-=1
                        return GM_log("response.status = " + response.status);
                    }
                }
            });
        }
    }
    function GetFileLink(info,flag)
    {
        var download_info=null;
        GM_xmlhttpRequest({
            method: "POST",
            url: 'http://proapi.115.com/app/chrome/downurl',
            headers: {
                'Content-Type':'application/x-www-form-urlencoded'
            },
            data: PostData({
                data:m115_encode('{"pickcode":"'+info[1]+'"}')
            }),
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                    download_info = response.response;
                    console.log(download_info);
                    var json=m115_decode(download_info.data);
                    console.log(info)
                    console.log(json)
                    var url=JSON.parse(json)[info[2]]['url']['url'];
                    console.log(url);
                    window.reqcount+=1
                    var resp=response.responseHeaders
                    var setcookie= DeleteCookie(resp)
                    var filecookie= null;
                    if(setcookie)
                    {
                        filecookie= setcookie;
                    }
                    try
                    {
                        CreateHashLink(url,info,filecookie,flag);
                    }
                    catch(err)
                    {
                        alert('请先登录115'+err);
                    }
                } else {
                    return GM_log("response.status = " + response.status);
                }
            }
        });
    }
    function  DownLoadFileFromSha1Links(links)
    {
        if (links=="")
        {
            alert("链接不能为空");
            return;
        }
        var uploadinfo=null;
        var cid=0;
        GM_xmlhttpRequest({
            method: "GET",
            url: 'http://proapi.115.com/app/uploadinfo',
            responseType: 'json',
            onload: function(response) {
                if (response.status === 200) {
                    uploadinfo = response.response;
                    document.cookie=window.cookie
                    try
                    {
                        var lines=links.split(/\r?\n/);
                        lines.forEach(function (line) {
                            if (line.trim()=="")
                            {
                                return;
                            }
                            var nsf=line.split('|');
                            if(nsf[0].substring(0,6)==hProtocol)
                            {
                                nsf[0]=nsf[0].substring(6);
                            }
                            if(nsf[0]!='' && nsf[1]!='' && nsf[2]!=''&& nsf[3]!=''&&nsf[2].length==40&&nsf[3].length==40)
                            {
                                DownFileBySha1JS(uploadinfo.userkey,uploadinfo.user_id,nsf[0],nsf[1],nsf[2],nsf[3]);
                            }
                            else
                            {
                                alert("链接格式错误!");
                            }
                        });
                    }
                    catch(err)
                    {
                        alert('请先登录115'+err);
                    }
                } else {
                    return GM_log("response.status = " + response.status);
                }
            }
        });
    }
    function DownFileBySha1JS(userkey,user_id,filename,filesize,fileid,preid)
    {
        var target='U_1_'+window.CID.toString();
        GM_xmlhttpRequest({
            method: 'POST',
            url: 'http://uplb.115.com/3.0/initupload.php?' + UrlData({
                isp: 0,
                appid: 0,
                appversion: '25.2.0',
                format: 'json',
                sig: GetSig(user_id, fileid, target, userkey),
            }),
            data: PostData({
                preid: preid,
                fileid: fileid,
                quickid:fileid,
                app_ver: '25.2.0',
                filename: filename,
                filesize: filesize,
                exif:'',
                target: target,
                userid:user_id
            }),
            responseType: 'json',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            },
            onload: function(response) {
                if (response.status === 200) {
                    if (response.response.status === 2) {
                        return console.log(''+filename+' 导入成功！');
                    } else {
                        return console.log(''+filename+' 导入失败！');
                    }
                } else {
                    return GM_log("response.status = " + response.status);
                }
            }
        });
    }
    function GetSha1LinkByliNode(liNode)
    {
        var type=(liNode.getAttribute("file_type"));
        var filename  = liNode.getAttribute('title');
        if(type=="0")
        {
            var fid  = liNode.getAttribute('cate_id');
            return [fid,filename];
        }
        else
        {
            var filesize =liNode.getAttribute('file_size');
            var sha1 =liNode.getAttribute('sha1');
            var pickcode=liNode.getAttribute('pick_code');
            var fid  = liNode.getAttribute('file_id');
            return [filename+'|'+filesize+'|'+sha1, pickcode,fid];
        }
    }
    function AddDownloadSha1Btn(jNode)
    {
        if (document.getElementById('downsha1')==null){
            var id=document.createElement('div');
            id.setAttribute('class','con');
            id.setAttribute('id','downsha1');
            var ia=document.createElement('a');
            ia.setAttribute('class','button');
            ia.setAttribute('href','javascript:;');
            var inode=document.createTextNode("导入");
            ia.appendChild(inode);
            id.appendChild(ia);
            jNode[0].appendChild(id);
            id.addEventListener('click', function (e) {
                var links= document.getElementById('js_offline_new_add').value
                DownLoadFileFromSha1Links(links);
                (document.getElementsByClassName('close')[2].click());
            })
        }
    }
    function AddCreateHashLinkBtn(jNode)
    {
        var parentNode=jNode[0].parentNode;
        var sha1Link=GetSha1LinkByliNode(parentNode);
        var aclass=document.createElement('a');

        aclass.addEventListener('click', function (e) {
            test(sha1Link,true);
        })
        var iclass=document.createElement('i');
        var ispan=document.createElement('span');
        var node=document.createTextNode("生成HashLink");
        ispan.appendChild(node);
        aclass.appendChild(iclass);
        aclass.appendChild(ispan);
        jNode[0].appendChild(aclass);
    }
})();
