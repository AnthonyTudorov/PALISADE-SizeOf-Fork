/*
 * @file
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC
// Note must be before all headers

#include <iostream>
#include "obfuscation/lwebpchcprf.cpp"
#include "obfuscation/lwebpchcprf.h"
#include "utils/parallel.h"

#include "utils/debug.h"

using namespace lbcrypto;

void test(const BPCHCPRF<DCRTPoly>& algorithm, const vector<vector<Matrix<int>>>& M, const vector<pair<string, bool>> cases) {
    TimeVar t;
    double processingTime;

    cout << "n = " << algorithm.GetRingDimension() << endl;
    cout << "log2 q = " << algorithm.GetLogModulus() << endl;

    TIC(t);
    auto key = algorithm.KeyGen();
    processingTime = TOC(t);
    cout << "Master Secret (Unconstrained) Key Generation: " << processingTime << "ms" << endl;

    TIC(t);
    auto constrainedKey = algorithm.Constrain(key, M);
    processingTime = TOC(t);
    cout << "Constrained Key Generation: " << processingTime << "ms" << endl;

    for (const auto& value : cases) {
        TIC(t);
        cout << "input: " << value.first << endl;
        const auto value1 = algorithm.Evaluate(key, value.first);
        const auto value2 = algorithm.Evaluate(constrainedKey, value.first);
        processingTime = TOC(t);
        cout << "Evaluation: 2 * " << processingTime / 2 << "ms" << endl;
        //cout << value1 << endl;
        //cout << value2 << endl;
        bool match = value1 == value2;
        cout << (match ? "Matched " : "Did not match ") << (match == value.second ? "(Correct)" : "(Incorrect)") << endl;
    }
}

void CC17Manual() {
    // M accepts 010? and 100?
    auto zero_alloc = []() { return 0; };
    Matrix<int> M_00(zero_alloc, 3, 3);
    M_00(0, 2) = 1;
    M_00(1, 1) = 1;
    M_00(2, 0) = 1;
    Matrix<int> M_01(zero_alloc, 3, 3);
    M_01(0, 2) = 1;
    M_01(1, 0) = 1;
    M_01(2, 1) = 1;
    Matrix<int> M_10(zero_alloc, 3, 3);
    M_10(0, 2) = 1;
    M_10(1, 1) = 1;
    M_10(2, 0) = 1;
    Matrix<int> M_11(zero_alloc, 3, 3);
    M_11(0, 1) = 1;
    M_11(1, 2) = 1;
    M_11(2, 0) = 1;
    Matrix<int> M_20(zero_alloc, 3, 3);
    M_20(0, 0) = 1;
    M_20(1, 2) = 1;
    M_20(2, 1) = 1;
    Matrix<int> M_21(zero_alloc, 3, 3);
    M_21(0, 1) = 1;
    M_21(1, 0) = 1;
    M_21(2, 2) = 1;
    Matrix<int> M_30(zero_alloc, 3, 3);
    M_30(0, 0) = 1;
    M_30(1, 1) = 1;
    M_30(2, 2) = 1;
    Matrix<int> M_31(zero_alloc, 3, 3);
    M_31(0, 0) = 1;
    M_31(1, 1) = 1;
    M_31(2, 2) = 1;
    vector<vector<Matrix<int>>> M = {{M_00, M_01}, {M_10, M_11}, {M_20, M_21}, {M_30, M_31}};

    CC17Algorithm<DCRTPoly> algorithm(1 << 15, 2, 4, 1024, 3);
    test(algorithm, M, {{"1001", true}, {"0110", false}});
}

void CVW18Disjunction(const string& pattern, const vector<pair<string, bool>>& cases) {
    // "10*0" -> x0 V -x1 V -x3
    auto zero_alloc = []() { return 0; };
    Matrix<int> I(zero_alloc, 2, 2);
    I(0, 0) = 1;
    I(1, 1) = 1;
    Matrix<int> N(zero_alloc, 2, 2);
    N(1, 1) = 1;
    Matrix<int> v(zero_alloc, 1, 2);
    v(0, 0) = 1;

    vector<vector<Matrix<int>>> M;
    for (const char& value : pattern) {
        if (value == '*') {
            M.push_back({I, I});
        } else if (value == '1') {
            M.push_back({I, N});
        } else {
            M.push_back({N, I});
        }
    }

    CVW18Algorithm<DCRTPoly> algorithm(1 << 15, 4, pattern.length(), 1024, v);
    test(algorithm, M, cases);
}

void CVW18HammingCloseness(const string& pattern, usint distance, const vector<pair<string, bool>>& cases) {
    const usint w = pattern.length();
    auto zero_alloc = []() { return 0; };
    Matrix<int> I(zero_alloc, w + 1, w + 1);
    for (usint i = 0; i <= w; i++) {
        I(i, i) = 1;
    }
    Matrix<int> N(zero_alloc, w + 1, w + 1);
    for (usint i = 0; i < w; i++) {
        N(i + 1, i) = 1;
    }
    N(0, w) = 1;
    Matrix<int> R(zero_alloc, w + 1, w + 1);
    R(0, 0) = 1;
    vector<vector<Matrix<int>>> M;
    for (const char& value : pattern) {
        if (value == '0') {
            M.push_back({I, N});
        } else if (value == '1') {
            M.push_back({N, I});
        }
    }
    M.back()[0] = M.back()[0] * R;
    M.back()[1] = M.back()[1] * R;
    Matrix<int> v(zero_alloc, 1, w + 1);
    for (usint i = distance + 1; i <= w; i++) {
        v(0, i) = 1;
    }

    CVW18Algorithm<DCRTPoly> algorithm(1 << 15, 2, w, 1024, v);
    test(algorithm, M, cases);
}

void CVW18WitnessEncryption() {
    WitnessEncryption<DCRTPoly> algorithm(1 << 15, 2, 1024, 4, 6);

    TimeVar t;
    double processingTime;

    cout << "n = " << algorithm.GetRingDimension() << endl;
    cout << "log2 q = " << algorithm.GetLogModulus() << endl;

    TIC(t);
    // clauses
    // -x0 V -x1 V -x2 V -x3
    // -x0 V -x1 V  x2
    // -x0 V  x1 V -x2 V  x3
    //  x0 V -x1 V -x2 V -x3
    //  x0 V -x1 V x2
    //  x0 V  x1
    auto ciphertext = algorithm.Encrypt({"0000", "001*", "0101", "1000", "101*", "11**"}, 0);
    processingTime = TOC(t);
    cout << "Encrypt: " << processingTime << "ms" << endl;

    TIC(t);
    const string input0 = "1001";
    const string input1 = "0010";
    usint value0 = algorithm.Decrypt(ciphertext, input0);
    usint value1 = algorithm.Decrypt(ciphertext, input1);
    processingTime = TOC(t);
    cout << "Decrypt: 2 * " << processingTime / 2 << "ms" << endl;
    cout << "input: " << input0 << endl;
    cout << value0 << (value0 == 0 ? " (Correct)" : " (Incorrect)") << endl;
    cout << "input: " << input1 << endl;
    cout << value1 << (value1 == 1 ? " (Correct)" : " (Incorrect)") << endl;
}

int main(int argc, char* argv[]) {

	PalisadeParallelControls.Enable();

    //CC17Manual();
    CVW18Disjunction("10*000*110*000*1", {{"0011111000111110", true}, {"0101110001011100", false}});
    //CVW18HammingCloseness("0010", 2, {{"1011", true}, {"1001", false}});
    //CVW18WitnessEncryption();
}
