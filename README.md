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

Env. variable | Description
---|---
`VAPID_PRIVATE_KEY` | Push messaging private key (registered in Firebase)
`VAPID_PUBLIC_KEY` | Push messaging public key (registered in Firebase)
`VAPID_CLAIMS_SUB` | Admin email, format: `mailto:yourmail@gmail.com`
`GOOGLE_SERVER_KEY` | Server key from Google Firebase Cloud Messaging
