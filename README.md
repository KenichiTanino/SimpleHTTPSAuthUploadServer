# SimpleHTTPSAuthUploadServer

Python SSL server using Basic auth and Simple Upload.

## Usage

```
$ SimpleHTTPSAuthUploadServer --https --auth 'aa:aa'
### or
$ python3 -m SimpleHTTPSAuthUploadServer --https --auth 'aa:aa'
```

### SSL(--https option)

If you use SSL, create a ".ssl" directory under your boot directory and store your private key and certificate in it.
