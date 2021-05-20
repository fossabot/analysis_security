#!/bin/bash

set -e

cd server
go get .

for f in ../tests/backwards_compatibility_DBs/*; do
    echo $f;
    timeout 10 go run . -k $f || [[ $? -eq 124 ]]
done
