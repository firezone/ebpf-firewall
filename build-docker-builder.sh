#!/bin/bash
pushd docker-builder
docker build -t bpf-builder .
popd