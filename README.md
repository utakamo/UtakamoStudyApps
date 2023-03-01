# UtakamoApps
This is application packages for openwrt. 

|  Application  |         description       |
| :---: | :---  |
|   duckdump    |   packet capture (IPv4)   |
|  uci-samplexx |   libuci sample program  |

Then follow these steps to compile package (ex duckdump).

1. Create the following feeds.conf in the OpenWrt directory  
```
#~/openwrt/feeds.conf
src-link utakamo /[your pc path]/UtakamoStudyApps/packages
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
The created package is in ~/openwrt/bin/packages/[target device chip]/utakamo.
```
user:~/openwrt$ make package/duckdump/compile
```
If you have never created a firmware image of the target device, then the package creation will fail. In that case, run "make V=s".

# MyWebSite
[Top Page](https://utakamo.com)  
[duckdump introduction page](https://utakamo.com/article/openwrt/beginner/intro05.html)  
[uci-samplexx introduction page](https://utakamo.com/article/openwrt/library/libuci-c.html)  
