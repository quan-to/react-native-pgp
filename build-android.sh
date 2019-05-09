#!/bin/bash

# GoMobile does not support Go Modules Yet
export GO111MODULE=off
go get
gomobile bind -x -v -target=android github.com/quan-to/react-native-pgp/chevronwrap
