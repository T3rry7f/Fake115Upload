# Fake115Upload_Python3
原项目<a title="Fake115Upload" target="_blank" href="https://github.com/T3rry7f/Fake115Upload">Fake115Upload</a>运行环境是Python2，修改为Python3

## 增加功能

#### 本地旧文件备份：

当在本地创建文件时（使用-o或-i ），
若本地存在同名旧文件，自动将旧文件重命名（文件名后增加时间戳）。

## 用法:
先在fake115upload.py的第17行填入自己的COOKIES

```
$root:python Fake115Upload.py 
Options:
-c cid:      指定115需要导入或导出的CID对应目录(默认为0，即根目录）。
-u filename: 从本地上传一个文件，支持秒传和普通上传两种方式。
-i filename: 从本地文本读取（文件名|文件大小|文件HASH值|块HASH）字段值并将其对应文件导入到115中。
-o filename: 从115中导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。
-b filename: 从本地当前目录导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。

```
