ARG http_proxy=http://proxy-dmz.intel.com:912
ARG https_proxy=http://proxy-dmz.intel.com:912
ARG no_proxy=intel.com

# Specifies a parent image
FROM golang:1.19.2-bullseye
 
# Creates an app directory to hold your app’s source code
WORKDIR /app
 
# Copies everything from your root directory into /app
COPY . .
 
# Installs Go dependencies
RUN go mod download
 
# Builds your app with optional configuration
RUN go build -o cve_scanner

FROM alpine:latest

RUN apk update
RUN apk upgrade
RUN apk add bash
RUN apk add libc6-compat

WORKDIR /

COPY --from=0 /app/cve_scanner .
 
# Tells Docker which network port your container listens on
EXPOSE 1323
 
# Specifies the executable command that runs when the container starts
CMD [ “/cve_scanner” ]
