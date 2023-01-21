# UtakamoApps
This is application packages for openwrt. 

|  Application  |         description       |
| :---: | :---  |
|   duckdump    |   packet capture (IPv4)   |
|  uci-samplexx |   libuci sample plrogram  |

Since this is for learning purposes, MakeFile's SOURCE_DIR specifies a local directory.  
When compiling, please adapt this part to your own PC environment. (Will change from local to via Git later.)    

ex) /UtakamoApps/package/duckdump/Makefile  
```
SOURCE_DIR:=[your local directory path (duckdump c source directory path)]    
```

Then follow these steps to compile.

1. Create the following feeds.conf in the OpenWrt directory  
```
#~/openwrt/feeds.conf
src-link utakamo /[your pc path]/UtakamoApps/packages
```

2. Execute the following command in the openwrt directory  
```
user:~/openwrt$ ./scripts/feeds update -a
user:~/openwrt$ ./scripts/feeds install -a -p
```

3. Execute "Make menuconfig" and Check the utakamo-->duckdump
```
user:~/openwrt$ make menuconfig
```

4. Compile with the following command  
The created package is in ~/openwrt/bin/package/utakamo.
```
user:~/openwrt$ make package/duckdump/compile
```

<a href="https://utakamo.com/">My Blog</a><br>
<a href="https://utakamo.com/article/openwrt/beginner/intro05.html">duckdumpの解説ページ</a><br>
<a href="https://utakamo.com/article/openwrt/library/libuci-c.html">uci-sampleXの解説ページ</a>
