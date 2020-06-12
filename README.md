# DXC RUN 4U - server

## Push notifications
Generate VAPID keys, for example using Node web-push:
```
npm install web-push -g
```
And then run
```
web-push generate-vapid-keys --json
```

## Environment variables
|---|---|  
VAPID_PRIVATE_KEY | ""
VAPID_PUBLIC_KEY | ""
VAPID_CLAIMS_SUB | Format: `mailto:yourmail@gmail.com`
GOOGLE_SERVER_KEY | Server key from Google Firebase Cloud Messaging
