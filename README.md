# Fake115Upload_Python3
原项目<a title="Fake115Upload" target="_blank" href="https://github.com/T3rry7f/Fake115Upload">Fake115Upload</a>运行环境是Python2，修改为Python3

上传本地一个文件的功能不保证稳定性。

## 增加功能

#### 本地旧文件备份：

当在本地创建文件时（使用-o或-i ），
若本地存在同名旧文件，自动将旧文件重命名（文件名后增加时间戳）。

#### 配置文件：

改成从配置文件读命令的方式，方便修改cookies

## 用法
按需求修改配置文件后，运行程序。

### 下载

[Windows版](https://github.com/LSD08KM/Fake115Upload_Python3/releases)

其他系统请clone源码包运行，并手动安装Python3环境

### 配置文件config.ini

```
[webhard]
COOKIES=			必填项！
option=uplinks		(要执行的命令) 填写option变量
upcid=0				(与upfile、uplinks命令对应) 指定上传到哪个CID目录，默认为0，即根目录
getcid=0			(与getlinks命令对应) 指定获取哪个CID目录的转存链 
upload_file_name=1.mp4			(与upfile命令对应) 要上传到网盘的文件全名，包括扩展名
uplinks_file=115uplinks.txt		(与uplinks命令对应) 存有要上传的转存链的本地文档
getlinks_file=115links.txt		(与getlinks、build命令对应) 
```
#### option变量（命令）：

```
upfile	从本地上传一个文件，支持秒传和普通上传两种方式。
uplinks	从本地文本读取（文件名|文件大小|文件HASH值|块HASH）字段值并将其对应文件导入到115中。
getlinks	从115中导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。
build	从本地当前目录导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。
```

#### CID在哪里：

在地址栏。
![](.\readme\1.png)
图中cid=0，即当前网页打开的文件夹目录的cid是0。

#### COOKIES在哪里：

在115浏览器打开网盘文件夹，点击键盘F12，出现DeveloperTools。再刷新网页，看DeveloperTools的Network栏，点击下面Name列表里files?开头的条目，右侧图中圈出的就是COOKIES。复制到配置文件即可。
![](.\readme\2.png)