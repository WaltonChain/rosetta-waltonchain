# Copyright 2020 Coinbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Compile golang
FROM ubuntu:20.04 as golang-builder

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app
WORKDIR /app

RUN apt-get update && apt-get install -y curl make gcc g++ git
ENV GOLANG_VERSION 1.16.8
ENV GOLANG_DOWNLOAD_SHA256 f32501aeb8b7b723bc7215f6c373abb6981bbc7e1c7b44e9f07317e1a300dce2
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
  && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf golang.tar.gz \
  && rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Compile gwtc
FROM golang-builder as geth-builder

# VERSION: WaltonChain_Gwtc_Src latest
RUN pwd
RUN sleep 30
RUN git clone https://github.com/WaltonChain/WaltonChain_Gwtc_Src.git \
  && cd WaltonChain_Gwtc_Src \
  && git checkout 8a298c95a819491400b86e271bd109a037fa2d08 \

RUN sleep 30

RUN mkdir -p $GOPATH/src/github.com/wtc
RUN sleep 3600
RUN mv WaltonChain_Gwtc_Src/ $GOPATH/src/github.com/wtc/go-wtc \
  && cd $GOPATH/src/github.com/wtc/go-wtc \
  && go env -w GO111MODULE="auto" \
  && cd cmd/gwtc \
  && go build

RUN mv $GOPATH/src/github.com/wtc/go-wtc/cmd/gwtc /app/gwtc \
  && rm -rf WaltonChain_Gwtc_Src $GOPATH/src/github.com

# Compile rosetta-waltonchain
#FROM golang-builder as rosetta-builder
#
## Use native remote build context to build in any directory
#COPY . src
#RUN cd src \
#  && go build
#
#RUN mv src/rosetta-waltonchain /app/rosetta-waltonchain \
#  && mkdir /app/waltonchain \
#  && mv src/waltonchain/call_tracer.js /app/waltonchain/call_tracer.js \
#  && mv src/waltonchain/geth.toml /app/waltonchain/geth.toml \
#  && rm -rf src
#
### Build Final Image
#FROM ubuntu:20.04
#
#RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates
#
#RUN mkdir -p /app \
#  && chown -R nobody:nogroup /app \
#  && mkdir -p /data \
#  && chown -R nobody:nogroup /data
#
#WORKDIR /app
#
## Copy binary from geth-builder
#COPY --from=geth-builder /app/gwtc /app/gwtc
#
## Copy binary from rosetta-builder
#COPY --from=rosetta-builder /app/waltonchain /app/waltonchain
#COPY --from=rosetta-builder /app/rosetta-waltonchain /app/rosetta-waltonchain
#
## Set permissions for everything added to /app
#RUN chmod -R 755 /app/*
#
#CMD ["/app/rosetta-waltonchain", "run"]
