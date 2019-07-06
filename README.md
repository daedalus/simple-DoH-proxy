# simple-DoH-proxy
A simple DNS over HTTPS proxy https://datatracker.ietf.org/doc/rfc8484/

```
  git clone https://github.com/daedalus/simple-DoH-proxy
  sudo python simple-DoH-proxy/DoHProxy.py 1.1.1.1
```

On a separate screen:
```
nslookup
> server 127.0.0.1
> example.com
```
