# 一个稳定的UDP反向端口映射方法
使用到的工具  
https://github.com/ring04h/udptunnel  
http://fuzz.wuyun.org/src/s5.py  

## 原理实例图
![](https://github.com/ring04h/rtcp2udp/blob/master/portmap_.png?20160505)  

## 编译可执行程序
```
server# git clone https://github.com/ring04h/udptunnel.git 
server# cd udptunnel 
server# make
```

## 服务端启动 UDP 53端口, 用于UDP隧道服务
假设服务器的外网IP为 119.29.29.29
```
server# ./udptunnel -s 119.29.29.29 53
```

## 客户端同样的方法编译可执行程序
在客户端，下载和启动socks5代理服务，端口为 1080
假设客户端的内网IP为 10.0.0.20
```
client# wget http://fuzz.wuyun.org/src/s5.py
client# nohup python s5.py 1080 &
```
===========================================================
使用udptunnel连接119.29.29.29的53/udp端口，打通隧道  
并将119.29.29.29的SSH服务端口映射为客户端10.0.0.20的2222端口

```
client$ ./udptunnel -c 10.0.0.20 2222 119.29.29.29 53 127.0.0.1 22
```
===========================================================
客户端10.0.0.20连接119.29.29.29的SSH服务，  
将10.0.0.20的1080端口代理服务，转发到119.29.29.29的1080上  
```
client$ ssh -C -f -N -g -R 1080:10.0.0.20:1080 ringzero@10.0.0.20 -p 2222
```
===========================================================
同理，可以转发内网的其它服务器的端口到远程服务器
```
client$ ssh -C -f -N -g -R 3306:172.168.1.10:3306 ringzero@10.0.0.20 -p 2222
```

全程都是使用53端口的UDP协议进行通信；
