#!/bin/bash

circom ./examples/sha256/circom/sha256_test.circom --r1cs --wasm --sym --c --output ./examples/sha256/circom/ --prime vesta

#Doesn't work on M1, using WASM instead
#cd examples/sha256/toy_cpp && make
