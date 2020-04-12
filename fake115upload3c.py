#coding: utf-8
__author__ = 'T3rry'
__Python3_author__ = 'LSD08KM'

import os,sys
import requests
import json
import hashlib
import codecs
import ctypes
import platform
import time
from configparser import ConfigParser
from requests_toolbelt.multipart.encoder import MultipartEncoder 


def set_cmd_text_color(color, handle):
    Bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
    return Bool

def resetColor(std_out_handle):
    set_cmd_text_color(0x0c | 0x0a | 0x09,std_out_handle)

def printInfo(info,erorr,notice=''):
    std_out_handle=0
    sysstr = platform.system()
    if erorr==True:
        if(sysstr =="Windows"):
            std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
            set_cmd_text_color(0x0c,std_out_handle)
            sys.stdout.write('['+notice+'] '+info+'\n')
            resetColor(std_out_handle)
        else : 
            print('\033[31m'+'['+notice+'] '+info)
    else:
        if(sysstr =="Windows"):
            std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
            set_cmd_text_color(0x0a,std_out_handle)
            sys.stdout.write('['+notice+'] '+info+'\n')
            resetColor(std_out_handle)
        else:
            print('\033[32m'+'['+notice+'] '+info)

def GetFileSize(file):
	return os.path.getsize(file)


'''
def ShowFolderPath(cid):
    url='https://webapi.115.com/files?aid=1&cid='+str(cid)+'&o=user_ptime&asc=0&offset=0&show_dir=1&limit=115&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&type=&star=&is_q=&is_share='
    r = requests.get(url,headers=header,cookies=d_cookie)
    resp=json.loads(r.content)['path']
    path='{'
    for f in resp:
        path+= f['name']+'=>'
    path=path[:-2]+'}'
    printInfo(path,False,"[PATH]")
'''


def Get115HashLink(filename):
    try:
        with open(filename,'rb') as f:
            sha = hashlib.sha1()
            sha.update(f.read(1024*128))
            BlockHASH = sha.hexdigest()
            f.seek(0,0)
            sha = hashlib.sha1()
            sha.update(f.read())
            TotalHASH=sha.hexdigest()
            return filename+'|'+str(os.path.getsize(filename))+'|'+TotalHASH+'|'+BlockHASH+'\n'
    except Exception as e:
        pass
def Export_115_links_from_local(outfile):
    print(os.getcwd())
    files = os.listdir(os.getcwd())
    of= codecs.open(outfile,'a+')
    for f in files:
        if os.path.isfile(f):
            print(f)
            ret= Get115HashLink(f)
            of.write(ret)
    of.close()



#==================================================
def AddCookie(COOKIES): ##给d_cookie赋值
    d_cookie={}
    if not ';' in COOKIES:
        print("[!] Cookies错误")
        return False
    for line in COOKIES.split(';'):
        if '=' in line:
            name,value=line.strip().split('=',1)  
            d_cookie[name]=value 
        else:
            print("[!] Cookies错误")
            return False
    return d_cookie
        
def GetFileSize(file):  #获得本地文件大小
	return os.path.getsize(file)
    
def GetUserKey(header, d_cookie):
    #需要参数  header, d_cookie 返回参数user_id, userkey
    #调用函数 AddCookie
    #传递参数 COOKIES
    #global user_id,userkey
    try:
        r = requests.get("http://proapi.115.com/app/uploadinfo",headers=header,cookies=d_cookie)
        resp=json.loads(r.content) 
        user_id = str(resp['user_id'])
        userkey = str(resp['userkey']).upper()
        return user_id, userkey
    except Exception as e:
        print("Explired Cookies")
        return False, False
def Upload_file_by_sha1(preid, fileid, filesize, filename, cid, pickcode, header, d_cookie):  #用转存码上传文件
    #需要参数 preid,fileid,filesize,filename,cid, pickcode, header, d_cookie
    #增加 , pickcode, header, d_cookie
    #调用函数 GetUserKey
    end_string="000000"
    app_ver='11.2.0' 

    user_id, userkey = GetUserKey(header, d_cookie)
    if user_id is False: return	
    fileid=fileid.upper()
    quickid=fileid
    target='U_1_'+str(cid)
    hash=hashlib.sha1((user_id+fileid+quickid+pickcode+target+'0').encode("utf8")).hexdigest()
    a=userkey+hash+end_string
    sig=hashlib.sha1(a.encode("utf8")).hexdigest().upper()
    URL="http://uplb.115.com/3.0/initupload.php?isp=0&appid=0&appversion=11.2.0&format=json&sig="+sig
    postData={
                'preid':preid,
                'filename':filename,
                'quickid':fileid,
                'user_id':user_id,
                'app_ver':app_ver,
                'filesize':filesize,
                'userid':user_id,
                'exif':'',
                'target':target,
                'fileid':fileid
              }
    r = requests.post(URL, data=postData,headers=header)
    #print r.content
    try:
        if json.loads(r.content)['status']==2 and json.loads(r.content)['statuscode']==0:
            printInfo(filename+' upload completed.',False,"OK")
            return True
        else:
            printInfo(filename+' upload failed.',True,"ERROR")
            return False
    except:
        return False

#==================================================
def Upload_localFile_whith_sha1(filename,cid, pickcode, header, d_cookie): #本地秒传 
    #调用函数 Upload_file_by_sha1
    #增加传递变量 , pickcode, header, d_cookie
    printInfo( "Trying fast upload...",False,"INFO")
    with open(filename,'rb') as f:
        sha = hashlib.sha1()
        sha.update(f.read(1024*128))
        BlockHASH = sha.hexdigest()
        f.seek(0,0)
        sha = hashlib.sha1()
        sha.update(f.read())
        TotalHASH=sha.hexdigest()
        ret=Upload_file_by_sha1(BlockHASH,TotalHASH,GetFileSize(filename),os.path.basename(filename),cid, pickcode, header, d_cookie)
        return ret    
def Upload_file_from_local(filename, cid, pickcode, header, d_cookie):  #上传本地单个文件
    #调用函数 Upload_localFile_whith_sha1; GetFileSize
    #需要参数 filename, cid, header, d_cookie, 
    #增加 , pickcode, header, d_cookie
    if Upload_localFile_whith_sha1(filename,cid):   #尝试秒传。改了global user_id,userkey的值
        return
    printInfo( "Trying local upload...",False,"INFO")
    
    user_id, userkey = GetUserKey(header, d_cookie)
    if user_id is False: return	    
    target='U_1_'+str(cid)
    uri='http://uplb.115.com/3.0/sampleinitupload.php'
    postdata={"userid":user_id,"filename":os.path.basename(filename),"filesize":GetFileSize(filename),"target":target}
    r = requests.post(uri,headers=header,cookies=d_cookie,data=postdata)
    resp=json.loads(r.content) 
    print(resp)
    req_headers = {'Content-Type': "multipart/form-data; boundary=----7d4a6d158c9"}
    m = MultipartEncoder(fields=[('name', os.path.basename(filename)), 
                             ('key', resp['object']),
                             ('policy',resp['policy']),
                             ('OSSAccessKeyId', resp['accessid']),
                             ('success_action_status', '200'),
                             ( 'callback',resp['callback']),
                             ('signature',resp['signature']),
                             ('file',(os.path.basename(filename),open(filename, 'rb'), 'video/mp4'))],
                            boundary='----7d4a6d158c9'
                    )
    r = requests.post(resp['host'],headers=req_headers,data=m)
    try:
        if json.loads(r.content)['state']==True and json.loads(r.content)['code']==0:
            printInfo(os.path.basename(filename)+' upload completed.',False,"OK")
        else:
            printInfo(os.path.basename(filename)+' upload failed.',False,"OK")
    except Exception as e:
        print('error',e)

def Upload_files_by_sha1_from_links(file, cid, pickcode, header, d_cookie):  #上传文档内的链接 sample : 1.mp4|26984894148|21AEB458C98643D5E5E4374C9D2ABFAAA4C6DA6
    #添加, pickcode, header, d_cookie
    for l in open(file,'r'):
        link=l.split('|')
        filename=link[0]
        filesize=link[1]
        fileid=link[2]
        preid=link[3].strip()
        if(len(fileid)!=40 and len(preid)!=40):
            print('Error Links')
            return
        #Upload_file_by_sha1(preid,fileid,filesize,filename,cid)
        Upload_file_by_sha1(preid, fileid, filesize, filename, cid, pickcode, header, d_cookie)
    print('[+] '+file+'内转存码上传结束')

def backupExistFile(path): #重命名已存在的文件，加上时间戳
    if os.path.exists(path):  
        print("[*]"+path+" exist! Will be back up.")
        time_stamp = int(time.time()) #时间戳
        file_timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime(time_stamp))#YYYYMMDDhh24miss  
        filename=os.path.splitext(path)[0] #文件名
        filetype=os.path.splitext(path)[1]
        Newpath=os.path.join(filename+"_"+file_timestamp+filetype)
        try:
            os.rename(path,Newpath) 
        except:
            print("[-]failed!can not rename file 'failed'\n[-](Please run as Administrator)")
            os._exit(0)

def GetPreidByPickcode(pickcode, header, d_cookie):
    #增加 , header, d_cookie
    downUrl='http://webapi.115.com/files/download?pickcode='+pickcode
    r = requests.get(downUrl,headers=header,cookies=d_cookie)
    file_url=json.loads(r.content)['file_url']
    head = { "User-Agent" : 'Mozilla/5.0  115disk/11.2.0',"Range":"bytes=0-131071"}
    cookie=r.headers['Set-Cookie'].split(';')[0]
    token= {cookie.split('=')[0]:cookie.split('=')[1]}
    r2= requests.get(file_url,headers=head,cookies=token)
    sha = hashlib.sha1()
    sha.update(r2.content)
    preid = sha.hexdigest()
    return preid.upper()
def Export_115_sha1_to_file(outfile, cid, header, d_cookie): #导出转存链到本地
    #！需要return FileCount
    #增加 , header, d_cookie
    FileCount = 0
    uri="http://webapi.115.com/files?aid=1&cid="+str(cid)+"&o=user_ptime&asc=0&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json"
    url='http://aps.115.com/natsort/files.php?aid=1&cid='+str(cid)+'&o=file_name&asc=1&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json&type=&star=&is_share=&suffix=&custom_order=&fc_mix='
    resp=''
    r = requests.get(uri,headers=header,cookies=d_cookie)
    if('data' in json.loads(r.content)):
        resp=json.loads(r.content)['data']
    else:
        r = requests.get(url,headers=header,cookies=d_cookie)
        resp=json.loads(r.content)['data']
    of= codecs.open(outfile,'a+', encoding='utf-8')
    for d in resp:	
        if 'fid' in d:
            FileCount+=1
            try:
                preid = GetPreidByPickcode(d['pc'], header, d_cookie) #pickcode
                printInfo(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid,False,str(FileCount))
                of.write(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid+'\n')
            except:
                of.write(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid+'\n')
            continue
        elif  'cid' in d:
            Export_115_sha1_to_file(outfile, d['cid'], header, d_cookie)
    of.close()
    return FileCount

#==================================================
if __name__ == '__main__':
    config_file = 'config.ini'  #获取 config.ini 内的变量
    config = ConfigParser()
    config.read(config_file, encoding='UTF-8')
    COOKIES = config['webhard']['COOKIES']
    option = config['webhard']['option']
    upcid = config['webhard']['upcid']
    getcid = config['webhard']['getcid']
    upload_file_name = config['webhard']['upload_file_name']
    uplinks_file = config['webhard']['uplinks_file']
    links_outfile = config['webhard']['links_outfile']
    
    pickcode="" #交给 Upload_file_by_sha1
    header = { "User-Agent" : 'Mozilla/5.0  115disk/11.2.0'}
    d_cookie = AddCookie(COOKIES)  #给 d_cookie 赋值
    if d_cookie is False:
        os._exit(0)

    if option == 'upfile':
        Upload_file_from_local(upload_file_name, upcid, pickcode, header, d_cookie)
    elif option == 'uplinks':
        Upload_files_by_sha1_from_links(uplinks_file, upcid, pickcode, header, d_cookie)
    elif option == 'getlinks':
        backupExistFile(links_outfile)
        FileCount = Export_115_sha1_to_file(links_outfile, getcid, header, d_cookie)
        print('[+] Total count is:',FileCount)
    elif option == 'build':
        backupExistFile(links_outfile)
        Export_115_links_from_local(links_outfile)
    else:
        print("[!] option变量错误!")
    print("[+] 运行结束!!!")
    input("[+][+] 按任意键关闭。")