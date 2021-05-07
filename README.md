Repository initially forked from https://github.com/skipper-plugins/filters

It contains:
- filter plugin  for JWT validation (./jwtvalidation)
- Dockerfile to build and package skipper with jwtvalidation plugin. 
  Unlike original skipper image it is based on ubuntu:latest because Go plugin mechanism seems to not work with alpine
- Azure build pipeline to build the image  


Currently, the plugin contains one single filter JwtValidation("<issuer-url>", "<space separated list of claims>")

Here is example of usage as an annotation in K8s Ingress. Following code instruct skipper check if header "Authorization" 
contains valid access token with "sub" claim in payload:
```
    zalando.org/skipper-filter: JwtValidationAnyClaims("https://login.microsoftonline.com/<tenant>/v2.0/", "sub")
```