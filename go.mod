module github.com/coinbase/rosetta-waltonchain

require (
	github.com/OneOfOne/xxhash v1.2.5 // indirect
	github.com/coinbase/rosetta-sdk-go v0.7.10
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ethereum/go-ethereum v1.13.10
	github.com/fatih/color v1.13.0
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/spf13/cobra v1.5.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/sync v0.5.0
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

//replace github.com/ethereum/go-ethereum => github.com/ethereum/go-ethereum v1.7.3
//replace github.com/ethereum/go-ethereum/crypto => github.com/ethereum/go-ethereum/crypto v1.10.0

go 1.16
