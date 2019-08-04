copy pasta from https://github.com/ipfs/dht-node

start many nodes, listen for handleAddProvider events, so you can
sniff to as much ipfs keys as possible [ effectively sybil attack ]

go run main.go -many 10 | grep KEY




