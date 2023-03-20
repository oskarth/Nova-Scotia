/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

// From https://raw.githubusercontent.com/celer-network/zk-benchmark/main/circom/circuits/sha256_test/sha256_test.circom
pragma circom 2.0.3;

include "sha256_bytes.circom";

template Sha256Test(N) {

    signal input in[N];
    signal input hash[32];
    signal output out[32];

    component sha256 = Sha256Bytes(N);
    sha256.in <== in;
    out <== sha256.out;

    for (var i = 0; i < 32; i++) {
        out[i] === hash[i];
    }

    log("start ================");
    for (var i = 0; i < 32; i++) {
        log(out[i]);
    }
    log("finish ================");
}

template Main(N) {

    signal input step_in[2];
    signal input in[N];
    signal input hash[32];

    signal output step_out[2];

    component sha256test = Sha256Test(N);

    // XXX Dummy constraint
    step_in[0] === step_in[1];

    for (var i = 0; i < N; i++) {
        sha256test.in[i] <== in[i];
    }

    for (var i = 0; i < 32; i++) {
        sha256test.hash[i] <== hash[i];
    }

    // TODO Replace this with output of hash
    // out <== sha256test.out;
    // XXX Dummy constraint
    step_out[0] <== step_in[0];
    step_out[1] <== step_in[1];
}

// render this file before compilation
component main { public [step_in] }= Main(64);