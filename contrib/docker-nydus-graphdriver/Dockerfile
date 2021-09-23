FROM golang:1.16
ARG GOPROXY="https://goproxy.cn,direct"
RUN mkdir -p /app
WORKDIR /app
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -v .

FROM alpine:3.13.6
RUN mkdir -p /plugin; mkdir -p /nydus
ARG NYDUSD_PATH=./nydusd
COPY --from=0 /app/nydus_graphdriver /plugin/nydus_graphdriver
COPY ${NYDUSD_PATH} /nydus
ENTRYPOINT [ "/plugin/nydus_graphdriver" ]