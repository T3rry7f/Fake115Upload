# Fake115Upload_Python3
原项目<a title="Fake115Upload" target="_blank" href="https://github.com/T3rry7f/Fake115Upload">Fake115Upload</a>运行环境是Python2，修改为Python3

*增加本地文件备份功能：*

当使用 `python Fake115Upload.py -o 115.txt` 从115导出字段到本地，或者使用`python Fake115Upload.py -i 115.txt`创建本地文件时，
若本地存在旧文件`115.txt`，自动将旧文件重命名。

# 用法:
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
# Environment:
  ```
  运行环境： Python3 
  ```

