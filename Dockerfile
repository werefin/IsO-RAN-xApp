FROM nexus3.o-ran-sc.org:10002/o-ran-sc/bldr-ubuntu20-c-go:1.0.0 as build-iso-ran

# Install utilities
RUN apt update && apt install -y iputils-ping net-tools curl sudo ca-certificates

# Install RMR shared library & development header files
RUN wget --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr_4.9.0_amd64.deb/download.deb && dpkg -i rmr_4.9.0_amd64.deb && rm -rf rmr_4.9.0_amd64.deb
RUN wget --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr-dev_4.9.0_amd64.deb/download.deb && dpkg -i rmr-dev_4.9.0_amd64.deb && rm -rf rmr-dev_4.9.0_amd64.deb

# Install dependencies, compile and test the module
RUN mkdir -p /go/src/iso-ran
COPY . /go/src/iso-ran

WORKDIR "/go/src/iso-ran"

ENV GO111MODULE=on GO_ENABLED=0 GOOS=linux

RUN go build -a -installsuffix cgo -o iso-ran iso-ran.go


# Final deployment container
FROM ubuntu:18.04

ENV CFG_FILE=config/config-file.json
ENV RMR_SEED_RT=config/uta_rtg.rt
ENV RMR_ATTACK_RT=rmr_payloads/rmr_empty_rt.raw

RUN mkdir /config
RUN mkdir /rmr_payloads

COPY --from=build-iso-ran /go/src/iso-ran/iso-ran /
COPY --from=build-iso-ran /go/src/iso-ran/config/* /config/
COPY --from=build-iso-ran /go/src/iso-ran/rmr_payloads/* /rmr_payloads/
COPY --from=build-iso-ran /usr/local/lib /usr/local/lib

RUN ldconfig

RUN chmod 755 /iso-ran
CMD /iso-ran
