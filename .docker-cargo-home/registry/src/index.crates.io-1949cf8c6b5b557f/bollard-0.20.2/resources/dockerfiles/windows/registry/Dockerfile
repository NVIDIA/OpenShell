FROM stefanscherer/golang-windows:1.9 as build

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ENV DOCKER_BUILDTAGS include_oss include_gcs
ENV DISTRIBUTION_VERSION v2.6.2

RUN mkdir src\github.com\docker ; \
    cd src\github.com\docker ; \
    git clone -q https://github.com/docker/distribution ; \
    cd distribution ; \
    git checkout -q $env:DISTRIBUTION_VERSION ; \
    try { go get github.com/tools/godep 2>&1 } catch { } ; \
    try { go get github.com/tools/godep } catch { } ; \
    Start-Process -FilePath godep.exe -ArgumentList go, build, ./cmd/registry -Wait

FROM mcr.microsoft.com/windows/nanoserver:10.0.14393.2068

COPY --from=build /gopath/src/github.com/docker/distribution/registry.exe /registry.exe
COPY config.yml /config/config.yml

VOLUME C:\\registry
EXPOSE 5000

ENTRYPOINT ["\\registry.exe"]
CMD ["serve", "/config/config.yml"]
