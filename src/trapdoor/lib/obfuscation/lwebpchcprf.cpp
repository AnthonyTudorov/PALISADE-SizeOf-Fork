/**
 * @file lwebpchcprf.cpp Implementation of constraint-hiding constrained PRFs for
 * branching programs as described in https://eprint.iacr.org/2017/143.pdf and
 * https://eprint.iacr.org/2018/360.pdf
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

#ifndef LBCRYPTO_OBFUSCATE_LWEBPCHCPRF_CPP
#define LBCRYPTO_OBFUSCATE_LWEBPCHCPRF_CPP

#include "lwebpchcprf.h"

namespace lbcrypto {

template <class Element>
BPCHCPRF<Element>::BPCHCPRF(usint base, usint chunkSize, usint length, usint n, usint w)
    : m_base(base), m_chunkSize(chunkSize), m_length(length), m_adjustedLength(length / chunkSize), m_chunkExponent(1 << m_chunkSize), m_w(w), m_dgg(SIGMA) {
    // Generate ring parameters
    double q = EstimateRingModulus(n);
    m_elemParams = GenerateElemParams(q, n);
    m_m = ceil(GetLogModulus() / log2(base)) + 2;

    // Initialize m_dggLargeSigma
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND(n, m_m - 2, base);

    if (sqrt(s * s - c * c) <= 3e5)
        m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
    else
        m_dggLargeSigma = m_dgg;
}

template <class Element>
usint BPCHCPRF<Element>::GetRingDimension() const {
    return m_elemParams->GetRingDimension();
}

template <class Element>
usint BPCHCPRF<Element>::GetLogModulus() const {
    double q = m_elemParams->GetModulus().ConvertToDouble();
    usint logModulus = floor(log2(q - 1.0) + 1.0);
    return logModulus;
}

template <class Element>
const pair<vector<vector<Element>>, Matrix<Element>> BPCHCPRF<Element>::KeyGen() const {
    typename Element::TugType tug;
    vector<vector<Element>> s;

    for (usint i = 0; i < m_adjustedLength; i++) {
        vector<Element> s_i;

        for (usint k = 0; k < m_chunkExponent; k++) {
            Element s_ik = Element(tug, m_elemParams, COEFFICIENT);
            s_ik.SwitchFormat();

            s_i.push_back(s_ik);
        }

        s.push_back(s_i);
    }

    auto uniform_alloc = Element::MakeDiscreteUniformAllocator(m_elemParams, EVALUATION);
    Matrix<Element> A_last(uniform_alloc, m_w, m_w * m_m);

    return make_pair(s, A_last);
}

template <class Element>
const pair<Matrix<Element>, vector<vector<Matrix<Element>>>> BPCHCPRF<Element>::Constrain(
    const pair<vector<vector<Element>>, Matrix<Element>>& key,
    const vector<vector<Matrix<int>>>& M) const {
    vector<vector<Element>> s = key.first;
    Matrix<Element> A = key.second;
    vector<vector<Matrix<Element>>> D;
    auto zero_alloc = Element::Allocator(m_elemParams, EVALUATION);

    for (int i = m_adjustedLength - 1; i >= 0; i--) {
        // Sample trapdoor pairs (for diagonal A_i)
        vector<pair<Matrix<Element>, RLWETrapdoorPair<Element>>> trapPairs;
        for (usint j = 0; j < m_w; j++) {
            trapPairs.push_back(RLWETrapdoorUtility<Element>::TrapdoorGen(m_elemParams, SIGMA, m_base));
        }

        // Sample D_i
        vector<Matrix<Element>> D_i;

        for (usint k = 0; k < m_chunkExponent; k++) {
            usint w = M[0][0].GetCols();
            // Compute M_ik
            Matrix<int> M_ik([]() { return 0; }, w, w);
            for (usint j = 0; j < w; j++) {
                M_ik(j, j) = 1;
            }
            for (usint j = 1, kk = k; j <= m_chunkSize; j++) {
                M_ik = M[(i + 1) * m_chunkSize - j][kk % 2] * M_ik;
                kk /= 2;
            }

            Matrix<Element> t = Gamma(M_ik, s[i][k]);
            D_i.push_back(Encode(trapPairs, A, t));
        }

        D.push_back(D_i);

        // Construct A_i
        A.Fill(zero_alloc());
        for (usint j = 0; j < m_w; j++) {
            for (usint o = 0; o < m_m; o++) {
                A(j, j * m_m + o) = trapPairs[j].first(0, o);
            }
        }
    }

    reverse(D.begin(), D.end());
    return make_pair(*m_J * A, D);
}

template <class Element>
const vector<Poly> BPCHCPRF<Element>::Evaluate(
    const pair<vector<vector<Element>>, Matrix<Element>>& key,
    const string& input) const {
    Element yCurrent;

    for (usint i = 0; i < m_adjustedLength; i++) {
        string chunk = input.substr(i * m_chunkSize, m_chunkSize);
        int k = stoi(chunk, nullptr, 2);

        if (i == 0)
            yCurrent = key.first[i][k];
        else
            yCurrent *= key.first[i][k];
    }

    Matrix<Element> y = yCurrent * key.second.ExtractRow(0);

    return TransformMatrixToPRFOutput(y);
}

template <class Element>
const vector<Poly> BPCHCPRF<Element>::Evaluate(
    const pair<Matrix<Element>, vector<vector<Matrix<Element>>>>& constrainedKey,
    const string& input) const {
    Matrix<Element> y = constrainedKey.first;

    for (usint i = 0; i < m_adjustedLength; i++) {
        std::string chunk = input.substr(i * m_chunkSize, m_chunkSize);
        int k = std::stoi(chunk, nullptr, 2);
        y = y * constrainedKey.second[i][k];
    }

    return TransformMatrixToPRFOutput(y);
}

template <class Element>
double BPCHCPRF<Element>::EstimateRingModulus(usint n) const {
    //smoothing parameter - also standard deviation for noise Elementnomials
    double sigma = SIGMA;

    //assurance measure
    double alpha = 36;

    //empirical parameter
    double beta = 6;

    //Bound of the Gaussian error Elementnomial
    double Berr = sigma * sqrt(alpha);

    uint32_t length = m_adjustedLength;
    uint32_t base = m_base;

    //Correctness constraint
    auto qCorrectness = [&](uint32_t n, uint32_t m, uint32_t k) -> double { return 32 * Berr * k * sqrt(n) * pow(sqrt(m * n) * beta * SPECTRAL_BOUND(n, m - 2, base), length); };

    double qPrev = 1e6;
    double q = 0;
    usint k = 0;
    usint m = 0;

    //initial value
    k = floor(log2(qPrev - 1.0) + 1.0);
    m = ceil(k / log2(base)) + 2;
    q = qCorrectness(n, m, k);

    //get a more accurate value of q
    while (std::abs(q - qPrev) > 0.001 * q) {
        qPrev = q;
        k = floor(log2(qPrev - 1.0) + 1.0);
        m = ceil(k / log2(base)) + 2;
        q = qCorrectness(n, m, k);
    }

    return q;
}

template <>
shared_ptr<typename DCRTPoly::Params> BPCHCPRF<DCRTPoly>::GenerateElemParams(double q, usint n) const {
    size_t dcrtBits = 60;
    size_t size = ceil((floor(log2(q - 1.0)) + 2.0) / (double)dcrtBits);

    vector<NativeInteger> moduli(size);
    vector<NativeInteger> roots(size);

    //makes sure the first integer is less than 2^60-1 to take advangate of NTL optimizations
    NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);
    firstInteger -= 2 * n * ((uint64_t)(1) << 40);
    moduli[0] = NextPrime<NativeInteger>(firstInteger, 2 * n);
    roots[0] = RootOfUnity<NativeInteger>(2 * n, moduli[0]);

    for (size_t i = 1; i < size; i++) {
        moduli[i] = NextPrime<NativeInteger>(moduli[i - 1], 2 * n);
        roots[i] = RootOfUnity<NativeInteger>(2 * n, moduli[i]);
    }

    shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

    ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots, 2 * n, moduli);

    return params;
}

template <class Element>
Matrix<Element> BPCHCPRF<Element>::Encode(
    const vector<pair<Matrix<Element>, RLWETrapdoorPair<Element>>>& trapPairs,
    const Matrix<Element>& A,
    const Matrix<Element>& matrix) const {
    usint n = GetRingDimension();
    auto zero_alloc = Element::Allocator(m_elemParams, EVALUATION);

    typename Element::DggType dgg = m_dgg;
    typename Element::DggType dggLargeSigma = m_dggLargeSigma;

    Matrix<Element> E(zero_alloc, m_w, m_w * m_m);
    for (usint i = 0; i < m_w; i++) {
        for (usint j = 0; j < m_w * m_m; j++) {
            E(i, j) = Element(dgg, m_elemParams, COEFFICIENT);
            E(i, j).SwitchFormat();
        }
    }

    Matrix<Element> Y = matrix * A + E;

    Matrix<Element> D(zero_alloc, m_w * m_m, m_w * m_m);

#ifdef OMP
#pragma omp parallel for schedule(dynamic)
#endif
    for (usint i = 0; i < m_w; i++) {
        for (usint j = 0; j < m_w * m_m; j++) {
            Matrix<Element> gaussj = RLWETrapdoorUtility<Element>::GaussSamp(n, m_m - 2, trapPairs[i].first, trapPairs[i].second, Y(i, j), dgg, dggLargeSigma, m_base);
            for (usint k = 0; k < m_m; k++) {
                D(i * m_m + k, j) = gaussj(k, 0);
            }
        }
    }

    return D;
}

template <class Element>
const vector<Poly> BPCHCPRF<Element>::TransformMatrixToPRFOutput(const Matrix<Element>& matrix) const {
    const BigInteger& q = m_elemParams->GetModulus();
    const BigInteger& half = m_elemParams->GetModulus() >> 1;

    vector<Poly> output(matrix.GetCols());

    for (usint i = 0; i < matrix.GetCols(); i++) {
        Poly poly = matrix(0, i).CRTInterpolate();

        // Transform negative numbers so that they could be rounded correctly
        for (usint k = 0; k < poly.GetLength(); k++) {
            if (poly[k] > half)
                poly[k] = q - poly[k];
        }

        output[i] = poly.DivideAndRound(half);
    }

    return output;
}

template <class Element>
CC17Algorithm<Element>::CC17Algorithm(usint base, usint chunkSize, usint length, usint n, usint w)
    : BPCHCPRF<Element>(base, chunkSize, length, n, w) {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> J(zero_alloc, 1, this->m_w);
    J(0, 0) = 1;
    this->m_J = make_shared<Matrix<Element>>(J);
}

template <class Element>
const Matrix<Element> CC17Algorithm<Element>::Gamma(const Matrix<int>& m, const Element& s) const {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> t(zero_alloc, this->m_w, this->m_w);
    for (usint x = 0; x < this->m_w; x++) {
        for (usint y = 0; y < this->m_w; y++) {
            t(x, y) = m(x, y) * s;
        }
    }
    return t;
}

template <class Element>
CVW18Algorithm<Element>::CVW18Algorithm(usint base, usint chunkSize, usint length, usint n, const Matrix<int>& v)
    : BPCHCPRF<Element>(base, chunkSize, length, n, v.GetCols() + 1) {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> J(zero_alloc, 1, this->m_w);
    J(0, 0) = 1;
    for (usint i = 1; i < this->m_w; i++) {
        J(0, i) = v(0, i - 1);
    }
    this->m_J = make_shared<Matrix<Element>>(J);
}

template <class Element>
const Matrix<Element> CVW18Algorithm<Element>::Gamma(const Matrix<int>& m, const Element& s) const {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> t(zero_alloc, this->m_w, this->m_w);
    t(0, 0) = s;
    for (usint x = 1; x < this->m_w; x++) {
        for (usint y = 1; y < this->m_w; y++) {
            t(x, y) = m(x - 1, y - 1) * s;
        }
    }
    return t;
}

template <class Element>
WitnessEncryption<Element>::WitnessEncryption(usint base, usint chunkSize, usint n, usint numVariables, usint numClauses)
    : BPCHCPRF<Element>(base, chunkSize, numVariables, n, numClauses + 1) {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> J(zero_alloc, 1, this->m_w);
    for (usint i = 0; i < this->m_w; i++) {
        J(0, i) = 1;
    }
    this->m_J = make_shared<Matrix<Element>>(J);
}

template <class Element>
const pair<Matrix<Element>, vector<vector<Matrix<Element>>>> WitnessEncryption<Element>::Encrypt(
    const vector<string>& cnf,
    usint message) const {
    // transform CNF to matrix BP
    // clause representation: "10*0" -> x0 V -x1 V -x3
    const usint numClauses = cnf.size();
    const usint numVariables = cnf[0].length();

    auto zero_alloc = []() { return 0; };
    Matrix<int> I(zero_alloc, numClauses + 1, numClauses + 1);
    I(0, 0) = message;
    for (usint i = 1; i <= numClauses; i++) {
        I(i, i) = 1;
    }

    vector<vector<Matrix<int>>> M;
    for (usint i = 0; i < numVariables; i++) {
        M.push_back({I, I});
    }

    for (usint i = 0; i < numClauses; i++) {
        for (usint j = 0; j < numVariables; j++) {
            if (cnf[i][j] == '1') {
                M[j][1](i + 1, i + 1) = 0;
            } else if (cnf[i][j] == '0') {
                M[j][0](i + 1, i + 1) = 0;
            }
        }
    }

    return this->Constrain(this->KeyGen(), M);
}

template <class Element>
usint WitnessEncryption<Element>::Decrypt(
    const pair<Matrix<Element>, vector<vector<Matrix<Element>>>> ciphertext,
    const string& x) const {
    const vector<Poly> output = this->Evaluate(ciphertext, x);
    BigInteger zero("0");
    usint value = 0;
    for (usint i = 0; i < output.size(); i++) {
        for (usint k = 0; k < output[i].GetLength(); k++) {
            if (output[i][k] > zero) {
                value = 1;
            }
        }
    }
    return value;
}

template <class Element>
const Matrix<Element> WitnessEncryption<Element>::Gamma(const Matrix<int>& m, const Element& s) const {
    auto zero_alloc = Element::Allocator(this->m_elemParams, EVALUATION);
    Matrix<Element> t(zero_alloc, this->m_w, this->m_w);
    for (usint x = 0; x < this->m_w; x++) {
        for (usint y = 0; y < this->m_w; y++) {
            t(x, y) = m(x, y) * s;
        }
    }
    return t;
}

}  // namespace lbcrypto

#endif
