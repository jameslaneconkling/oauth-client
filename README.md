# oauth-client

## Configure

**generate public/private key pair**
```bash
openssl genrsa -aes256 -out private.pem 2048

openssl rsa -pubout -in private.pem -out public.pem
```

**configure profiles.clj**

## Develop
```bash
lein ring server-headless
```

## Build
```bash
lein ring uberjar 
```
