# One image with everything: the control server, the gateway agent, and the
# client downloads (Windows installer, Windows agent, stclient test client)
# under /opt/securetunnel/clients, served by the control server's /downloads/.
FROM golang:1.26-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends nsis unzip \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ARG VERSION=0.1.0

# go.sum is generated here until it is committed to the repo.
RUN go mod tidy

# Checks: Linux packages, then the Windows-only agent code.
RUN CGO_ENABLED=0 go vet ./... \
 && CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet ./cmd/agent/ ./internal/... \
 && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go vet ./cmd/agent/

# Server side.
RUN mkdir -p /out/bin /out/clients \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bin/controlserver ./cmd/controlserver \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bin/gatewayagent ./cmd/gatewayagent \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/clients/stclient-linux ./cmd/stclient \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/clients/stclient.exe ./cmd/stclient

# Windows agent: icon + manifest resources, then the exe (GUI subsystem).
RUN go run ./tools/genicon installer/ \
 && go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest gui \
      --icon installer/icon.png --product-name SecureTunnel --file-description "SecureTunnel VPN" \
      --product-version "$VERSION" --file-version "$VERSION" --out cmd/agent/rsrc \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
      -ldflags="-s -w -H windowsgui -X main.version=$VERSION" -o installer/securetunnel.exe ./cmd/agent

# Official signed WireGuard driver (wireguard-nt) from wireguard.com.
RUN curl -fsSL -o /tmp/wireguard-nt.zip https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip \
 && sha256sum /tmp/wireguard-nt.zip \
 && unzip -j /tmp/wireguard-nt.zip 'wireguard-nt/bin/amd64/wireguard.dll' -d installer/

# Installer.
RUN cd installer \
 && makensis -V2 -DVERSION="$VERSION" securetunnel.nsi \
 && cp SecureTunnel-Setup.exe securetunnel.exe /out/clients/ \
 && echo "$VERSION" > /out/clients/windows-version.txt

# Mac agent: Apple silicon + Intel binaries (no cgo; the Go linker ad-hoc
# signs arm64 binaries, which Apple silicon requires). The downloads page
# builds the zip installer from them, and the .pkg too when bomutils' mkbom
# is available in this image.
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /tmp/mac/arm64 ./cmd/agent \
 && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /tmp/mac/amd64 ./cmd/agent \
 && go run ./tools/mkmacpkg -arm64 /tmp/mac/arm64 -amd64 /tmp/mac/amd64 -version "$VERSION" -out /out/clients/macos

FROM alpine:3.20
RUN apk add --no-cache ca-certificates iptables
COPY --from=build /out/bin/ /usr/local/bin/
COPY --from=build /out/clients/ /opt/securetunnel/clients/
EXPOSE 8443
CMD ["controlserver"]
