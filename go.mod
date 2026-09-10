module github.com/xarvel/CensorPulseCli

go 1.26.8

require (
	github.com/quic-go/quic-go v0.62.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/andybalholm/brotli v1.2.4 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
