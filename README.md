# Fake115Upload
模拟115客户端的上传功能，支持本地文件上传及网盘文件(hash)批量导入和导出。(谨慎使用批量导入导出功能，115本身并未提供此类功能，出了问题概不负责。）
  
  推荐使用油猴插件版：[安装地址](https://greasyfork.org/ja/scripts/386724-115%E4%B8%80%E9%94%AE%E8%BD%AC%E5%AD%98)

# Installation

下载代码，并安装依赖
```
git clone https://github.com/meoww-bot/Fake115Upload
cd Fake115Upload
pip install -r requirements.txt
```
打开 115 浏览器，获取 cookies 操作参考 [issues#10](https://github.com/T3rry7f/Fake115Upload/issues/10#issuecomment-619754476)

修改 `fake115upload.py` 第 16 行
```
COOKIES="your cookie"
```
引号内改为你的 cookies。

# Usage:
```
$root: python Fake115Upload.py 
Options:
-c cid:      指定115需要导入或导出的CID对应目录(默认为0，即根目录）。
-u filename: 从本地上传一个文件，支持秒传和普通上传两种方式。
-i filename: 从本地文本读取（文件名|文件大小|文件HASH值|块HASH）字段值并将其对应文件导入到115中。
-o filename: 从115中导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。
-b filename: 从本地当前目录导出所有文件的（文件名|文件大小|文件HASH值|块HASH）字段值到本地文本。

```

# Example:

上传本地某一目录中深度为 1 的文件，已在群晖上测试:
```
dir=<dir>;for i in $dir/*; do if [ -f "$i" ]; then python fake115upload.py  -c <cid> -u "$i"; fi ; done
```
群晖系统中，每个目录下有一个 `@eaDir` 目录，需要排除掉，所以有个 `if` 判断.

需要替换 `<dir>` 和 `<cid>`。

实例如下:
```
dir=10mu;for i in $dir/*; do if [ -f "$i" ]; then python fake115upload.py  -c 1817035256482495506 -u "$i"; fi ; done
```
# Environment:
  ```
  运行环境： Python2 
  平台支持 ：Windows/Linux/OSX （已测试）
  ```


# ScreenShot:
   
  ![avatar](https://raw.githubusercontent.com/T3rry7f/Fake115Upload/master/screenshot.png)


