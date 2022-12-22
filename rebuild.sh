#!/bin/sh -ex

docker run --name build-kit --interactive --tty \
--mount "type=bind,source=$(pwd)/node/ton-labs-executor,target=/ton-node/ton-labs-executor" \
build-kit /bin/bash -c "/root/.cargo/bin/cargo build --release"

docker cp build-kit:/ton-node/target/release/ton_node_startup ton-node
docker rm build-kit

docker rm --force evernode-se

docker create --name evernode-se -e USER_AGREEMENT=yes -p80:80 tonlabs/evernode-se
docker cp ton-node evernode-se:/node/
rm ton-node

docker start evernode-se
