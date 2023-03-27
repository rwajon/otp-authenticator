# TOTP/HOTP genarator and validator

# REST API
## Generate a `base32` secret
### Request
`GET /api/otp/secret?length=64`
```
curl "http://localhost:5050/api/otp/secret?length=64" -H "Accept: application/json"
```
### Response
```
HTTP/1.1 201 Created
Content-length: 294
Content-type: application/json
Date: Mon, 01 Jan 1970 00:00:00 GMT

{
  "secret": "9CDD323DCFF8EE626D",
  "uri": "otpauth://totp/Authenticator?secret=9CDD323DCFF8EE626D&algorithm=SHA1&digits=6&period=60",
  "qr_code": "https://chart.googleapis.com/chart?chs=400x400&chld=M&cht=qr&chl=otpauth://totp/Authenticator?secret=9CDD323DCFF8EE626D&algorithm=SHA1&digits=6&period=60"
}
```

## Generate a OTP
### Request
| Key | type | description |
|--------|------|-------------|
| `secret`| text | shared secret key (`required`) |
| `counter`| number | the counter value, calculated from time by default (`optional`) |
| `digits`| number | the number of digits for the token (`optional`) |
| `period`| number | the time to live of the token. Default 30 seconds (`optional`) |

`POST /api/otp/generate`
```
curl -X POST http://localhost:5050/api/otp/generate \
  -H 'Content-Type: application/json' \
  -d '{"secret":"9CDD323DCFF8EE626D"}'
```
### Response
```
HTTP/1.1 201 Created
Content-length: 18
Content-type: application/json
Date: Mon, 01 Jan 1970 00:00:00 GMT

{
  "token": "759346"
}
```

## Validate an OTP
|Key | Type | Description |
|--------|------|-------------|
| `token`| text | OTP to validate (`required`) |
| `secret`| text | shared secret key (`required`) |
| `counter`| number | the counter value, calculated from time by default (`optional`) |
| `period`| number | the time to live of the token. Default 30 seconds (`optional`) |
| `window`| number | the allowable margin for the counter (`optional`) |

### Request
`POST /api/otp/validate`
```
curl -X POST http://localhost:5050/api/otp/validate \
  -H 'Content-Type: application/json' \
  -d '{"secret":"9CDD323DCFF8EE626D", "token": "062435"}'
```
### Response
```
HTTP/1.1 200 Created
Content-length: 42
Content-type: application/json
Date: Mon, 01 Jan 1970 00:00:00 GMT

{
  "is_valid": true,
  "message": "OTP is valid"
}
```

# License
MIT

