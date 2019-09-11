#!/usr/local/bin/python
#coding: utf-8
__author__ = 'T3rry'

import os,sys
import requests
import json
import hashlib
import getopt
import codecs
import ctypes
import platform
from requests_toolbelt.multipart.encoder import MultipartEncoder 
#from pycookiecheat import chrome_cookies
#############################################################  Need your cookie
COOKIES="your cookie"
#############################################################  Need your cookie
#d_cookie=chrome_cookies('http://115.com')
d_cookie={}
user_id=""
userkey=""
target="U_1_0"
end_string="000000"
app_ver='11.2.0'
pickcode=""
FileCount=0
std_out_handle=0
header = { "User-Agent" : 'Mozilla/5.0  115disk/11.2.0'}

def usage():
    print(
"""
Usage:
-l filename: Upload a file form local
-i filename: Import files form a hash link list
-o filename: Export all hash links to file from 115
-m filename: Export all hash links to file from local
"""
)

def set_cmd_text_color(color, handle=std_out_handle):
    Bool = ctypes.windll.kernel32.SetConsoleTextAttribute(handle, color)
    return Bool

def resetColor():
    set_cmd_text_color(0x0c | 0x0a | 0x09,std_out_handle)

def printInfo(info,erorr,notice=''):
	global std_out_handle
	sysstr = platform.system()
	if erorr==True:
	  	if(sysstr =="Windows"):
	  		std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
			set_cmd_text_color(0x0c,std_out_handle)
			sys.stdout.write('['+notice+'] '+info+'\n')
			resetColor()
		else : 
			print '\033[31m'+'['+notice+'] '+info
	else:
		if(sysstr =="Windows"):
			std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
			set_cmd_text_color(0x0a,std_out_handle)
			sys.stdout.write('['+notice+'] '+info+'\n')
			resetColor()
		else:
			print '\033[32m'+'['+notice+'] '+info

def GetFileSize(file):
	return os.path.getsize(file)

def GetUserKey():
	global user_id,userkey
	if AddCookie(COOKIES) is False: return False
	try:
		r = requests.get("http://proapi.115.com/app/uploadinfo",headers=header,cookies=d_cookie)
		resp=json.loads(r.content) 
		user_id=str(resp['user_id'])
		userkey=str(resp['userkey']).upper()
	except Exception as e:
		print "Explired Cookies"
		return False

def GetPreidByPickcode(pickcode):
	downUrl='http://webapi.115.com/files/download?pickcode='+pickcode
	r = requests.get(downUrl,headers=header,cookies=d_cookie)
	file_url=json.loads(r.content)['file_url']
	head = { "User-Agent" : 'Mozilla/5.0  115disk/11.2.0',"Range":"bytes=0-131071"}
	cook=r.headers['Set-Cookie'].split(';')[0]
	token= {cook.split('=')[0]:cook.split('=')[1]}
	r2= requests.get(file_url,headers=head,cookies=token)
	sha = hashlib.sha1()
	sha.update(r2.content)
	preid = sha.hexdigest()
	return preid.upper()

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

def AddCookie(cook):
	for line in COOKIES.split(';'):
		if '=' in line:
			name,value=line.strip().split('=',1)  
			d_cookie[name]=value 

		elif not d_cookie :
			print "ERROR Cookies"
			return False

def Upload_file_by_sha1(preid,fileid,filesize,filename,cid):  #quick
	if GetUserKey() is False: return	
	fileid=fileid.upper()
	quickid=fileid
	target='U_1_'+str(cid)
	print target
	hash=hashlib.sha1((user_id+fileid+quickid+pickcode+target+'0')).hexdigest()
	a=userkey+hash+end_string
	sig=hashlib.sha1(a).hexdigest().upper()
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
def Upload_files_by_sha1_from_links(file,cid):  # sample : 1.mp4|26984894148|21AEB458C98643D5E5E4374C9D2ABFAAA4C6DA6
	for l in open(file,'r'):
		link=l.split('|')
		filename=link[0]
		filesize=link[1]
		fileid=link[2]
		preid=link[3].strip()
		if(len(fileid)!=40 and len(preid)!=40):
			print 'Error Links'
			return
		Upload_file_by_sha1(preid,fileid,filesize,filename,cid)

def Upload_localFile_whith_sha1(filename): #fast 
	printInfo( "Trying fast upload...",False,"INFO")
	with open(filename,'rb') as f:
		sha = hashlib.sha1()
		sha.update(f.read(1024*128))
		BlockHASH = sha.hexdigest()
		f.seek(0,0)
		sha = hashlib.sha1()
		sha.update(f.read())
		TotalHASH=sha.hexdigest()
		ret=Upload_file_by_sha1(BlockHASH,TotalHASH,GetFileSize(filename),os.path.basename(filename))
        return ret

def Upload_file_from_local(filename):  

	if Upload_localFile_whith_sha1(filename):
		return

	printInfo( "Trying local upload...",False,"INFO")
	uri='http://uplb.115.com/3.0/sampleinitupload.php'

	postdata={"userid":user_id,"filename":os.path.basename(filename),"filesize":GetFileSize(filename),"target":target}
	r = requests.post(uri,headers=header,cookies=d_cookie,data=postdata)
	resp=json.loads(r.content) 
	#print resp
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
		print 'error',e
	
def Export_115_sha1_to_file(outfile,cid='0'): #
	global FileCount
	uri="http://webapi.115.com/files?aid=1&cid="+str(cid)+"&o=user_ptime&asc=0&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json"
	url='http://aps.115.com/natsort/files.php?aid=1&cid='+str(cid)+'&o=file_name&asc=1&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json&type=&star=&is_share=&suffix=&custom_order=&fc_mix='
	if AddCookie(COOKIES) is False: return
	resp=''
	r = requests.get(uri,headers=header,cookies=d_cookie)
	if(json.loads(r.content).has_key('data')):
		resp=json.loads(r.content)['data']
	else:
		r = requests.get(url,headers=header,cookies=d_cookie)
		resp=json.loads(r.content)['data']
	of= codecs.open(outfile,'a+', encoding='utf-8')
	for d in resp:	
		if d.has_key('fid'):
			FileCount+=1
			try:
				preid=GetPreidByPickcode(d['pc'])
				printInfo(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid,False,str(FileCount))
				of.write(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid+'\n')
			except:
				of.write(d['n']+'|'+str(d['s'])+'|'+d['sha']+'|'+preid+'\n')
			continue
		elif  d.has_key('cid'):
			Export_115_sha1_to_file(outfile,d['cid'])
	of.close()

def Export_115_links_from_local(outfile):
	print os.getcwd()
	files = os.listdir(os.getcwd())
	of= codecs.open(outfile,'a+')
	for f in files:
		if os.path.isfile(f):
			print f
			ret= Get115HashLink(f)
			of.write(ret)
	of.close()
			
if __name__ == '__main__':
	if len(sys.argv) == 1:
		usage()
		sys.exit()
	cid=0
	try:
		opts, args = getopt.getopt(sys.argv[1:], "l:i:o:m:c:", ["help", "output="])
		for n,v in opts:
			if n in ('-c','--cid'):
				cid=v
			elif n in ('-l','--local'):
				Upload_file_from_local(v)	
			elif n in ('-i','--infile'):
				Upload_files_by_sha1_from_links(v,cid)				
			elif n in ('-o','--outfile'):
				print cid
				Export_115_sha1_to_file(v,cid)
				print 'Total count is:',FileCount
			elif n in ('-m','--outfile'):
				Export_115_links_from_local(v)
							
	except getopt.GetoptError:
		print("Argv error,please input")
		
