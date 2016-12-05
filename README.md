A simple socks5 proxy based on asyncio
======================================

Usage
-----

### *Genereate the certificate and key files*
```
openssl req -newkey rsa:2048 -nodes -keyout ssl.key -x509 -days 1095 -out ssl.crt

```

### *On server side*
```
$ python3 server.py -s 0.0.0.0 -p 10000

```

### *On client side*
```
$ python3 client -s <server-ip> -l 1080

```

### *Get help*
```
$ python3 client.py --help
usage: server.py [-h] [-c CONFIG] [-s SERVER_IP] [-p SERVER_PORT] [-b BIND_IP]
                 [-l LISTEN_PORT] [-t CRT_FILE] [-k KEY_FILE] [-v LOG_LEVEL]
                 [-f LOG_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file
  -s SERVER_IP, --server_ip SERVER_IP
                        server ip
  -p SERVER_PORT, --server_port SERVER_PORT
                        server port
  -b BIND_IP, --bind_ip BIND_IP
                        bind ip
  -l LISTEN_PORT, --listen_port LISTEN_PORT
                        listen port
  -t CRT_FILE, --crt_file CRT_FILE
                        crt file
  -k KEY_FILE, --key_file KEY_FILE
                        key file
  -v LOG_LEVEL, --log_level LOG_LEVEL
                        log level
  -f LOG_FILE, --log_file LOG_FILE
                        log file
```

##### *Python version support*
```
3.4+
```
