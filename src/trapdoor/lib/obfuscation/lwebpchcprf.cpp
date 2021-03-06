/**
 * @file lwebpchcprf.cpp Implementation of constraint-hiding constrained PRFs for
 * branching programs as described in https://eprint.iacr.org/2017/143.pdf and
 * https://eprint.iacr.org/2018/360.pdf
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include "utils/debug.h"

#include "obfuscation/lwebpchcprf.h"

namespace lbcrypto {

template <class Element>
BPCHCPRF<Element>::BPCHCPRF(usint base, usint chunkSize, usint length, usint n, usint w)
    : m_base(base), m_chunkSize(chunkSize), m_length(length), m_adjustedLength(length / chunkSize), m_chunkExponent(1 << m_chunkSize), m_w(w), m_dgg(SIGMA) {
    // Generate ring parameters
    double qEst = EstimateRingModulus(n);
    m_elemParams = GenerateElemParams(qEst, n);
    m_m = ceil(GetLogModulus() / log2(base)) + 2;

    // Initialize m_dggLargeSigma
    double c = (base + 1) * SIGMA;
    double s = SPECTRAL_BOUND_D(n, m_m - 2, base, w);

    if (sqrt(s * s - c * c) <= KARNEY_THRESHOLD)
    {
        m_dggLargeSigma = typename Element::DggType(sqrt(s * s - c * c));
    }
    else
    {
        m_dggLargeSigma = m_dgg;
    }

	size_t size = m_elemParams->GetParams().size();

	BigInteger q(m_elemParams->GetModulus());

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);
	for (size_t i = 0; i < size; i++){
		moduli[i] = m_elemParams->GetParams()[i]->GetModulus();
		roots[i] = m_elemParams->GetParams()[i]->GetRootOfUnity();
	}

	const BigInteger deltaBig = q.DividedBy(NativeInteger(2));

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(m_elemParams->GetParams()[i]->GetModulus().ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	NativeInteger p = NativeInteger(2);

	if (moduli[0].GetMSB() < 45)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<double> CRTDecryptionFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionFloatTable[i] = (double)numerator/(double)denominator;
		}
		m_CRTDecryptionFloatTable = CRTDecryptionFloatTable;
	}
	else if (moduli[0].GetMSB() < 58)
	{
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<long double> CRTDecryptionExtFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionExtFloatTable[i] = (long double)numerator/(long double)denominator;
		}
		m_CRTDecryptionExtFloatTable = CRTDecryptionExtFloatTable;
	}
	else
	{
#ifndef NO_QUADMATH
		//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used only in MultipartyDecryptionFusion
		std::vector<QuadFloat> CRTDecryptionQuadFloatTable(size);

		for (size_t i = 0; i < size; i++){
			BigInteger qi = BigInteger(moduli[i].ConvertToInt());
			int64_t numerator = ((q.DividedBy(qi)).ModInverse(qi) * BigInteger(p)).Mod(qi).ConvertToInt();
			int64_t denominator = moduli[i].ConvertToInt();
			CRTDecryptionQuadFloatTable[i] = ext_double::quadFloatFromInt64(numerator)/ext_double::quadFloatFromInt64(denominator);
		}
		m_CRTDecryptionQuadFloatTable = CRTDecryptionQuadFloatTable;
#else
			PALISADE_THROW(math_error, "BPCHCPRF: Number of bits in CRT moduli should be in < 58 for this architecture");
	
#endif	
	}

	//compute the table of integer factors floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p - used in decryption

	std::vector<NativeInteger> qDecryptionInt(size);
	std::vector<NativeInteger> qDecryptionIntPrecon(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = q / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*BigInteger(p)/qi;
		qDecryptionInt[vi] = quotient.Mod(p).ConvertToInt();
		qDecryptionIntPrecon[vi] = qDecryptionInt[vi].PrepModMulPreconOptimized(p);
	}

	m_CRTDecryptionIntTable = qDecryptionInt;
	m_CRTDecryptionIntPreconTable = qDecryptionIntPrecon;

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
    //typename Element::TugType tug;
    vector<vector<Element>> s;

    for (usint i = 0; i < m_adjustedLength; i++) {
        vector<Element> s_i(m_chunkExponent);

#pragma omp parallel for schedule(dynamic)
        for (usint k = 0; k < m_chunkExponent; k++) {
            Element s_ik = Element(m_dgg, m_elemParams, COEFFICIENT);
            s_ik.SwitchFormat();

            s_i[k] = s_ik;
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
        pair<Matrix<Element>, RLWETrapdoorPair<Element>> trapPair = RLWETrapdoorUtility<Element>::TrapdoorGenSquareMat(m_elemParams, SIGMA, m_w, m_base);

        // Sample D_i
        vector<Matrix<Element>> D_i(m_chunkExponent, Matrix<Element>(zero_alloc));

#pragma omp parallel for schedule(dynamic)
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
            D_i[k] = Encode(trapPair, A, t);
        }

        D.push_back(D_i);

        A = trapPair.first;
    }

    reverse(D.begin(), D.end());
    return make_pair(*m_J * A, D);
}

template <class Element>
shared_ptr<vector<NativePoly>> BPCHCPRF<Element>::Evaluate(
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

    Element y = key.second(0,1) * yCurrent;

    return TransformMatrixToPRFOutput(y);

}

template <class Element>
shared_ptr<vector<NativePoly>> BPCHCPRF<Element>::Evaluate(
    const pair<Matrix<Element>, vector<vector<Matrix<Element>>>>& constrainedKey,
    const string& input) const {
    Matrix<Element> y = constrainedKey.first;

    for (usint i = 0; i < m_adjustedLength; i++) {
        std::string chunk = input.substr(i * m_chunkSize, m_chunkSize);
        int k = std::stoi(chunk, nullptr, 2);
        y = y * constrainedKey.second[i][k];
    }

    return TransformMatrixToPRFOutput(y(0,1));

}

template <class Element>
double BPCHCPRF<Element>::EstimateRingModulus(usint n) const {
    //smoothing parameter - also standard deviation for noise Elementnomials
    double sigma = SIGMA;

    //assurance measure
    double alpha = 36;

    //empirical parameter
    double beta = 6;

    //probability of hitting the "danger" zone that affects the rounding result
	double Pe = 1 << 20;

    //Bound of the Gaussian error Elementnomial
    double Berr = sigma * sqrt(alpha);

    uint32_t length = m_adjustedLength;
    uint32_t base = m_base;

    //Correctness constraint
    auto qCorrectness = [&](uint32_t n, uint32_t m, uint32_t k) -> double
    		{ return 1024 * Berr * Pe * m_w * pow(sqrt(m_w * m * n) * beta * SPECTRAL_BOUND_D(n, m - 2, base, m_w), length-1); };

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

    std::cout << "q = " << q << std::endl;

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
    const pair<Matrix<Element>, RLWETrapdoorPair<Element>>& trapPair,
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
    for (usint i = 0; i < m_m; i++) {
        Matrix<Element> Y_i(zero_alloc, m_w, m_w);
        for (usint j = 0; j < m_w; j++) {
            for (usint k = 0; k < m_w; k++) {
                Y_i(j, k) = Y(j, i * m_w + k);
            }
        }

        Matrix<Element> D_i = RLWETrapdoorUtility<Element>::GaussSampSquareMat(n, m_m - 2, trapPair.first, trapPair.second, Y_i, dgg, dggLargeSigma, m_base);
        for (usint j = 0; j < m_w * m_m; j++) {
            for (usint k = 0; k < m_w; k++) {
                D(j, i * m_w + k) = D_i(j, k);
            }
        }
    }

    return D;
}

template <class Element>
shared_ptr<vector<NativePoly>> BPCHCPRF<Element>::TransformMatrixToPRFOutput(const Element& input) const {

	const std::vector<double> &lyamTable = m_CRTDecryptionFloatTable;
	const std::vector<long double> &lyamExtTable = m_CRTDecryptionExtFloatTable;
#ifndef NO_QUADMATH
	const std::vector<QuadFloat> &lyamQuadTable = m_CRTDecryptionQuadFloatTable;
#endif
	const std::vector<NativeInteger> &invTable = m_CRTDecryptionIntTable;
	const std::vector<NativeInteger> &invPreconTable = m_CRTDecryptionIntPreconTable;

	/*
	shared_ptr<vector<NativePoly>> result(new vector<NativePoly>(matrix.GetCols()));

	for (size_t i = 0; i < matrix.GetCols(); i++) {
		(*result)[i] = matrix(0, i).ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
	}
	*/

	shared_ptr<vector<NativePoly>> result(new vector<NativePoly>(1));

        auto element = input;
        element.SwitchFormat();

	// For PRF, it is sufficient to use 128 coefficients; we currently use n coefficients
#ifndef NO_QUADMATH
		(*result)[0] = element.ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamQuadTable,lyamExtTable);
#else
		(*result)[0] = element.ScaleAndRound(NativeInteger(2),invTable,lyamTable,invPreconTable,lyamExtTable);
#endif

	return result;

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
    shared_ptr<vector<NativePoly>> output = this->Evaluate(ciphertext, x);
    NativeInteger zero("0");
    usint value = 0;
    for (usint i = 0; i < output->size(); i++) {
        for (usint k = 0; k < (*output)[i].GetLength(); k++) {
            if ((*output)[i][k] > zero) {
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
