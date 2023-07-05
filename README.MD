
# owa_info
用于对Exchange的基础信息进行搜集的小脚本。

工具会探测Exchange的版本，并尝试去获取内网IP地址和Exchange主机名。

## Usage
```
usage: owa_info.py [-h] -u URL [-t TIMEOUT] [-d]

OWA Info Scanner

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Exchange OWA URL
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout
  -d, --debug           Print Debug info
```

## Example


![](https://blogpics-1251691280.file.myqcloud.com/imgs/202203231717908.png)

## Fofa
利用fofa去搜索Exchange可用以下搜索
```
microsoft exchange 2013：
app="Microsoft-Exchange-2013"||app="Microsoft-Exchange-Server-2013-CU21"||app="Microsoft-Exchange-Server-2013-CU17"||app="Microsoft-Exchange-Server-2013-CU23"||app="Microsoft-Exchange-Server-2013-CU13"||app="Microsoft-Exchange-Server-2013-CU22"||app="Microsoft-Exchange-Server-2013-CU11"||app="Microsoft-Exchange-Server-2013-CU2"||app="Microsoft-Exchange-Server-2013-CU16"||app="Microsoft-Exchange-Server-2013-CU19"||app="Microsoft-Exchange-Server-2013-CU3"||app="Microsoft-Exchange-Server-2013-CU18"||app="Microsoft-Exchange-Server-2013-CU5"||app="Microsoft-Exchange-Server-2013-CU20"||app="Microsoft-Exchange-Server-2013-CU12"||app="Microsoft-Exchange-Server-2013-CU15"||app="Microsoft-Exchange-Server-2013-CU10"||app="Microsoft-Exchange-Server-2013-CU9"||app="Microsoft-Exchange-Server-2013-CU6"||app="Microsoft-Exchange-Server-2013-CU7"||app="Microsoft-Exchange-Server-2013-CU1"||app="Microsoft-Exchange-Server-2013-CU14"||app="Microsoft-Exchange-Server-2013-CU8"||app="Microsoft-Exchange-Server-2013-RTM"||app="Microsoft-Exchange-Server-2013-SP1"||app="Microsoft-Exchange-2013"

microsoft exchange 2016：
app="Microsoft-Exchange-Server-2016-CU19"||app="Microsoft-Exchange-Server-2016-CU3"||app="Microsoft-Exchange-Server-2016-CU12"||app="Microsoft-Exchange-Server-2016-RTM"||app="Microsoft-Exchange-Server-2016-CU7"||app="Microsoft-Exchange-Server-2016-CU17"||app="Microsoft-Exchange-Server-2016-CU2"||app="Microsoft-Exchange-Server-2016-CU1"||app="Microsoft-Exchange-Server-2016-CU14"||app="Microsoft-Exchange-Server-2016-CU5"||app="Microsoft-Exchange-Server-2016-CU11"||app="Microsoft-Exchange-Server-2016-CU9"||app="Microsoft-Exchange-Server-2016-CU16"||app="Microsoft-Exchange-Server-2016-CU10"||app="Microsoft-Exchange-Server-2016-CU6"||app="Microsoft-Exchange-Server-2016-CU13"||app="Microsoft-Exchange-Server-2016-CU18"||app="Microsoft-Exchange-Server-2016-CU8"||app="Microsoft-Exchange-Server-2016-CU4"||app="Microsoft-Exchange-2016-POP3-server"

microsoft exchange 2019：
app="Microsoft-Exchange-Server-2019-CU5"||app="Microsoft-Exchange-Server-2019-CU3"||app="Microsoft-Exchange-Server-2019-Preview"||app="Microsoft-Exchange-Server-2019-CU8"||app="Microsoft-Exchange-Server-2019-CU1"||app="Microsoft-Exchange-Server-2019-CU7"||app="Microsoft-Exchange-Server-2019-CU2"||app="Microsoft-Exchange-Server-2019-CU6"||app="Microsoft-Exchange-Server-2019-RTM"||app="Microsoft-Exchange-Server-2019-CU4"

microsoft exchange 2010：
app="Microsoft-Exchange-2010-POP3-server-version-03.1"||app="Microsoft-Exchange-Server-2010"
```


## IIS 通过401/30X获取内网IP
Usage: 
```
Use to get the internal ip of IIS.

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  target url
```

example：
```
╰─❯ python get_internal_ip.py -u https://exchange.cgdomain.com/owa/
[*] Try to access https://exchange.cgdomain.com/owa
[*] Try to access https://exchange.cgdomain.com/owa/
[+] Internal ip:
	👉  10.211.55.201
```

## HealthChecker
对于运维人员，可使用以下脚本来检测自己Exchange服务器是否存在漏洞。

https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1