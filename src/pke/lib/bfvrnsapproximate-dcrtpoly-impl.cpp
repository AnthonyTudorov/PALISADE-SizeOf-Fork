/*
* @file bfvrnsapproximate-dcrtpoly-impl.cpp - dcrtpoly implementation for the BFV scheme using approximatation techniques.
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

#include "cryptocontext.h"
#include "bfvrnsapproximate.cpp"

#define PROFILE

//#define BFVrns_APPROXIMATE_DEBUG

namespace lbcrypto {


// TODO remove these utility functions
template<typename T>
void PrintSTDVector(const std::vector<T> &in)
{
	for (auto i: in)
		std::cout << i << ' ';

	cout << endl;
}
template<typename T>
void PrintSTDMat(const std::vector<std::vector<T>> &in)
{
	for(auto i = in.begin(); i != in.end(); i++)
	{
	    for(auto j = i->begin(); j != i->end(); j++)
	        std::cout << *j << ' ';

	    cout << endl;
	}
	cout << endl;
}
void PrintNTLPoly( const DCRTPoly &in )
{
	cout << in.CRTInterpolate() << endl;
}

// Precomputation of CRT tables encryption, decryption, and homomorphic multiplication
template <>
bool LPCryptoParametersBFVrnsApproximate<DCRTPoly>::PrecomputeCRTTables(){

	// read values for the CRT basis

	size_t size = GetElementParams()->GetParams().size();
	size_t n = GetElementParams()->GetRingDimension();

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	m_qModuli.resize(size);

	for (size_t i = 0; i < size; i++){
		moduli[i] = GetElementParams()->GetParams()[i]->GetModulus();
		roots[i] = GetElementParams()->GetParams()[i]->GetRootOfUnity();
		m_qModuli[i] = moduli[i];
	}

	ChineseRemainderTransformFTT<NativeInteger,NativeVector>::PreCompute(roots,2*n,moduli);

	// computes the auxiliary CRT basis S=s1*s2*..sn used in homomorphic multiplication

	size_t sizeS = size + 1;

	vector<NativeInteger> moduliS(sizeS);
	vector<NativeInteger> rootsS(sizeS);

	moduliS[0] = NextPrime<NativeInteger>(moduli[size-1], 2 * n);
	rootsS[0] = RootOfUnity<NativeInteger>(2 * n, moduliS[0]);

	for (size_t i = 1; i < sizeS; i++)
	{
		moduliS[i] = NextPrime<NativeInteger>(moduliS[i-1], 2 * n);
		rootsS[i] = RootOfUnity<NativeInteger>(2 * n, moduliS[i]);
	}

	m_paramsS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliS, rootsS));

	ChineseRemainderTransformFTT<NativeInteger,NativeVector>::PreCompute(rootsS,2*n,moduliS);

	// stores the parameters for the auxiliary expanded CRT basis Q*S = v1*v2*...*vn used in homomorphic multiplication

	vector<NativeInteger> moduliExpanded(size + sizeS);
	vector<NativeInteger> rootsExpanded(size + sizeS);

	// populate moduli for CRT basis Q
	for (size_t i = 0; i < size; i++ ) {
		moduliExpanded[i] = moduli[i];
		rootsExpanded[i] = roots[i];
	}

	// populate moduli for CRT basis S
	for (size_t i = 0; i < sizeS; i++ ) {
		moduliExpanded[size + i] = moduliS[i];
		rootsExpanded[size + i] = rootsS[i];
	}

	m_paramsQS = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, moduliExpanded, rootsExpanded));

	//compute the table of floating-point factors ((p*[(Q/qi)^{-1}]_qi)%qi)/qi - used in decryption

	std::vector<QuadFloat> CRTDecryptionFloatTable(size);

	const BigInteger modulusQ = GetElementParams()->GetModulus();

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		int64_t numerator = ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus())).Mod(qi).ConvertToInt();
		int64_t denominator = moduli[i].ConvertToInt();
		CRTDecryptionFloatTable[i] = quadFloatFromInt64(numerator)/quadFloatFromInt64(denominator);
	}

	m_CRTDecryptionFloatTable = CRTDecryptionFloatTable;

	//compute the table of integer factors floor[(p*[(Q/qi)^{-1}]_qi)/qi]_p - used in decryption

	std::vector<NativeInteger> qDecryptionInt(size);
	std::vector<NativeInteger> qDecryptionIntPrecon(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		BigInteger quotient = (divBy.ModInverse(qi))*BigInteger(GetPlaintextModulus())/qi;
		qDecryptionInt[vi] = quotient.Mod(GetPlaintextModulus()).ConvertToInt();
		qDecryptionIntPrecon[vi] = qDecryptionInt[vi].PrepModMulPreconNTL(GetPlaintextModulus());
	}

	m_CRTDecryptionIntTable = qDecryptionInt;
	m_CRTDecryptionIntPreconTable = qDecryptionIntPrecon;

	//compute the CRT delta table floor(Q/p) mod qi - used for encryption

	const BigInteger deltaBig = modulusQ.DividedBy(GetPlaintextModulus());

	std::vector<NativeInteger> CRTDeltaTable(size);

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduli[i].ConvertToInt());
		BigInteger deltaI = deltaBig.Mod(qi);
		CRTDeltaTable[i] = NativeInteger(deltaI.ConvertToInt());
	}

	m_CRTDeltaTable = CRTDeltaTable;

	//compute the (Q/qi)^{-1} mod qi table - used for homomorphic multiplication and key switching

	std::vector<NativeInteger> qInv(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		BigInteger divBy = modulusQ / qi;
		qInv[vi] = divBy.ModInverse(qi).Mod(qi).ConvertToInt();
	}

	m_CRTInverseTable = qInv;

	// compute the (Q/qi) mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> qDivqiModsi(sizeS);
	std::vector<std::vector<NativeInteger>> qDivqiModsiPrecon(sizeS);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduli[vIndex].ConvertToInt());
			BigInteger divBy = modulusQ / qi;
			qDivqiModsi[newvIndex].push_back(divBy.Mod(si).ConvertToInt());
			qDivqiModsiPrecon[newvIndex].push_back(qDivqiModsi[newvIndex][vIndex].PrepModMulPreconNTL(si.ConvertToInt()));
		}
	}

	m_CRTqDivqiModsiTable = qDivqiModsi;
	m_CRTqDivqiModsiPreconTable = qDivqiModsiPrecon;

	// compute the Q mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> qModsi(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		qModsi[vi] = modulusQ.Mod(si).ConvertToInt();
	}

	m_CRTqModsiTable = qModsi;

	// compute the [p*S*(Q*S/vi)^{-1}]_vi / vi table - used for homomorphic multiplication

	std::vector<double> precomputedDCRTMultFloatTable(size);

	const BigInteger modulusS = m_paramsS->GetModulus();
	const BigInteger modulusQS = m_paramsQS->GetModulus();

	const BigInteger modulusP( GetPlaintextModulus() );

	for (size_t i = 0; i < size; i++){
		BigInteger qi = BigInteger(moduliExpanded[i].ConvertToInt());
		precomputedDCRTMultFloatTable[i] =
				((modulusQS.DividedBy(qi)).ModInverse(qi)*modulusS*modulusP).Mod(qi).ConvertToDouble()/qi.ConvertToDouble();
	}

	m_CRTMultFloatTable = precomputedDCRTMultFloatTable;

	// compute the floor[p*S*[(Q*S/vi)^{-1}]_vi/vi] mod si table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> multInt(size+1);
	std::vector<std::vector<NativeInteger>> multIntPrecon(size+1);
	for( usint newvIndex = 0 ; newvIndex < sizeS; newvIndex++ ) {
		BigInteger si = BigInteger(moduliS[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < size; vIndex++ ) {
			BigInteger qi = BigInteger(moduliExpanded[vIndex].ConvertToInt());
			BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(qi)).ModInverse(qi));
			BigInteger divBy = num / qi;
			multInt[vIndex].push_back(divBy.Mod(si).ConvertToInt());
			multIntPrecon[vIndex].push_back(multInt[vIndex][newvIndex].PrepModMulPreconNTL(si.ConvertToInt()));
		}

		BigInteger num = modulusP*modulusS*((modulusQS.DividedBy(si)).ModInverse(si));
		BigInteger divBy = num / si;
		multInt[size].push_back(divBy.Mod(si).ConvertToInt());
		multIntPrecon[size].push_back(multInt[size][newvIndex].PrepModMulPreconNTL(si.ConvertToInt()));
	}

	m_CRTMultIntTable = multInt;
	m_CRTMultIntPreconTable = multIntPrecon;

	// compute the (S/si)^{-1} mod si table - used for homomorphic multiplication

	std::vector<NativeInteger> sInv(sizeS);
	for( usint vi = 0 ; vi < sizeS; vi++ ) {
		BigInteger si = BigInteger(moduliS[vi].ConvertToInt());
		BigInteger divBy = modulusS / si;
		sInv[vi] = divBy.ModInverse(si).Mod(si).ConvertToInt();
	}

	m_CRTSInverseTable = sInv;

	// compute (S/si) mod qi table - used for homomorphic multiplication

	std::vector<std::vector<NativeInteger>> sDivsiModqi(size);
	std::vector<std::vector<NativeInteger>> sDivsiModqiPrecon(size);
	for( usint newvIndex = 0 ; newvIndex < size; newvIndex++ ) {
		BigInteger qi = BigInteger(moduli[newvIndex].ConvertToInt());
		for( usint vIndex = 0 ; vIndex < sizeS; vIndex++ ) {
			BigInteger si = BigInteger(moduliS[vIndex].ConvertToInt());
			BigInteger divBy = modulusS / si;
			sDivsiModqi[newvIndex].push_back(divBy.Mod(qi).ConvertToInt());
			sDivsiModqiPrecon[newvIndex].push_back(sDivsiModqi[newvIndex][vIndex].PrepModMulPreconNTL(qi.ConvertToInt()));
		}
	}

	m_CRTsDivsiModqiTable = sDivsiModqi;
	m_CRTsDivsiModqiPreconTable = sDivsiModqiPrecon;

	// compute S mod qi table - used for homomorphic multiplication

	std::vector<NativeInteger> sModqi(size);
	for( usint vi = 0 ; vi < size; vi++ ) {
		BigInteger qi = BigInteger(moduli[vi].ConvertToInt());
		sModqi[vi] = modulusS.Mod(qi).ConvertToInt();
	}

	m_CRTsModqiTable = sModqi;













	// init Bajard's et al RNS variant lookup tables

	// Populate EvalMulrns tables
	// find the a suitable size of B
	m_numq = size;

	BigInteger t = BigInteger(GetPlaintextModulus());
	BigInteger q(GetElementParams()->GetModulus());

	BigInteger B = 1;
	BigInteger maxConvolutionValue = 4 * n * q * q * t;

	m_BModuli.push_back( NextPrime<NativeInteger>(moduli[m_numq-1], 2 * n) );

	m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_BModuli[0]) );
	B = B * m_BModuli[0];

	int i = 1; // we already added one prime
	while ( q*B < maxConvolutionValue )
	{
		m_BModuli.push_back( NextPrime<NativeInteger>(m_BModuli[i-1], 2 * n) );
		m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_BModuli[i]) );

		B = B * m_BModuli[i];
		i++;
	}

	m_numB = i;

	// find msk
	m_msk = NextPrime<NativeInteger>(m_BModuli[m_numB-1], 2 * n);
	m_BskRoots.push_back( RootOfUnity<NativeInteger>(2 * n, m_msk) );

	m_BskModuli = m_BModuli;
	m_BskModuli.push_back( m_msk );

	m_BskmtildeModuli = m_BskModuli;

	m_paramsBsk = shared_ptr<ILDCRTParams<BigInteger>>(new ILDCRTParams<BigInteger>(2 * n, m_BskModuli, m_BskRoots));

	// find m_tilde
	m_mtilde = NextPrime<NativeInteger>(m_msk, 2 * n);

	m_BskmtildeModuli.push_back( m_mtilde );

	// Populate (q/qi)^-1 mod qi
	m_qDivqiModqiTable.resize(m_numq);
	for (uint32_t i = 0; i < m_qDivqiModqiTable.size() ; i++ )
	{
		BigInteger qDivqi;
		qDivqi = q.DividedBy(moduli[i]) ;
		qDivqi = qDivqi.Mod(moduli[i]);
		qDivqi = qDivqi.ModInverse( moduli[i] );
		m_qDivqiModqiTable[i] = qDivqi.ConvertToInt();
	}

	// Populate t*(q/qi)^-1 mod qi
	m_tqDivqiModqiTable.resize(m_numq);
	m_tqDivqiModqiPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_tqDivqiModqiTable.size() ; i++ )
	{
		BigInteger tqDivqi;
		tqDivqi = q.DividedBy(moduli[i]) ;
		tqDivqi = tqDivqi.Mod(moduli[i]);
		tqDivqi = tqDivqi.ModInverse( moduli[i] );
		tqDivqi = tqDivqi.ModMul( t.ConvertToInt() , moduli[i] );
		m_tqDivqiModqiTable[i] = tqDivqi.ConvertToInt();
		m_tqDivqiModqiPreconTable[i] = m_tqDivqiModqiTable[i].PrepModMulPreconNTL( moduli[i] );
	}

	// Populate q/qi mod Bj table where Bj \in {Bsk U mtilde}
	m_qDivqiModBskmtildeTable.resize(m_numq);
	m_qDivqiModBskmtildePreconTable.resize(m_numq);

	for (uint32_t i = 0; i < m_qDivqiModBskmtildeTable.size(); i++)
	{
		m_qDivqiModBskmtildeTable[i].resize( m_numB + 2);
		m_qDivqiModBskmtildePreconTable[i].resize( m_numB + 2);

		BigInteger qDivqi = q.DividedBy(moduli[i]);
		for (uint32_t j = 0; j < m_qDivqiModBskmtildeTable[i].size(); j++)
		{
			BigInteger qDivqiModBj = qDivqi.Mod(m_BskmtildeModuli[j]);
			m_qDivqiModBskmtildeTable[i][j] = qDivqiModBj.ConvertToInt();
			m_qDivqiModBskmtildePreconTable[i][j] = m_qDivqiModBskmtildeTable[i][j].PrepModMulPreconNTL( m_BskmtildeModuli[j] );
		}
	}

	// Populate mtilde*(q/qi)^-1 mod qi table
	m_mtildeqDivqiTable.resize(m_numq);
	m_mtildeqDivqiPreconTable.resize(m_numq);

	for (uint32_t i = 0; i < m_mtildeqDivqiTable.size() ; i++ )
	{
		BigInteger qDivqi = q.DividedBy(moduli[i]);
		qDivqi = qDivqi.Mod(moduli[i]);
		qDivqi = qDivqi.ModInverse( moduli[i] );
		qDivqi = qDivqi * m_mtilde;
		qDivqi = qDivqi.Mod(moduli[i]);
		m_mtildeqDivqiTable[i] = qDivqi.ConvertToInt();
		m_mtildeqDivqiPreconTable[i] = m_mtildeqDivqiTable[i].PrepModMulPreconNTL( moduli[i] );
	}

	// Populate -1/q mod mtilde
	BigInteger negqInvModmtilde = ((m_mtilde-1) * q.ModInverse(m_mtilde));
	negqInvModmtilde = negqInvModmtilde.Mod(m_mtilde);
	m_negqInvModmtilde = negqInvModmtilde.ConvertToInt();
	m_negqInvModmtildePrecon = m_negqInvModmtilde.PrepModMulPreconNTL(m_mtilde);

	// Populate q mod Bski
	m_qModBskiTable.resize(m_numB + 1);
	m_qModBskiPreconTable.resize(m_numB + 1);

	for (uint32_t i = 0; i < m_qModBskiTable.size(); i++)
	{
		BigInteger qModBski = q.Mod(m_BskModuli[i]);
		m_qModBskiTable[i] = qModBski.ConvertToInt();
		m_qModBskiPreconTable[i] = m_qModBskiTable[i].PrepModMulPreconNTL(m_BskModuli[i]);
	}

	// Populate mtilde^-1 mod Bski
	m_mtildeInvModBskiTable.resize( m_numB + 1 );
	m_mtildeInvModBskiPreconTable.resize( m_numB + 1 );
	for (uint32_t i = 0; i < m_mtildeInvModBskiTable.size(); i++)
	{
		BigInteger mtildeInvModBski = m_mtilde % m_BskModuli[i];
		mtildeInvModBski = mtildeInvModBski.ModInverse(m_BskModuli[i]);
		m_mtildeInvModBskiTable[i] = mtildeInvModBski.ConvertToInt();
		m_mtildeInvModBskiPreconTable[i] = m_mtildeInvModBskiTable[i].PrepModMulPreconNTL(m_BskModuli[i]);
	}

	// Populate m_tPrecon
	m_tPrecon.PrepModMulPreconNTL( t.ConvertToInt() );

	// Populate q^-1 mod Bski
	m_qInvModBskiTable.resize(m_numB + 1);
	m_qInvModBskiPreconTable.resize(m_numB + 1);

	for (uint32_t i = 0; i < m_qInvModBskiTable.size(); i++)
	{
		BigInteger qInvModBski = q.ModInverse(m_BskModuli[i]);
		m_qInvModBskiTable[i] = qInvModBski.ConvertToInt();
		m_qInvModBskiPreconTable[i] = m_qInvModBskiTable[i].PrepModMulPreconNTL( m_BskModuli[i] );
	}

	// Populate (B/Bi)^-1 mod Bi
	m_BDivBiModBiTable.resize(m_numB);
	m_BDivBiModBiPreconTable.resize(m_numB);

	for (uint32_t i = 0; i < m_BDivBiModBiTable.size(); i++)
	{
		BigInteger BDivBi;
		BDivBi = B.DividedBy(m_BModuli[i]) ;
		BDivBi = BDivBi.Mod(m_BModuli[i]);
		BDivBi = BDivBi.ModInverse( m_BModuli[i] );
		m_BDivBiModBiTable[i] = BDivBi.ConvertToInt();
		m_BDivBiModBiPreconTable[i] = m_BDivBiModBiTable[i].PrepModMulPreconNTL(m_BModuli[i]);
	}

	// Populate B/Bi mod qj table (Matrix) where Bj \in {q}
	m_BDivBiModqTable.resize(m_numB);
	m_BDivBiModqPreconTable.resize(m_numB);

	for (uint32_t i = 0; i < m_BDivBiModqTable.size(); i++)
	{
		m_BDivBiModqTable[i].resize(m_numq);
		m_BDivBiModqPreconTable[i].resize(m_numq);
		BigInteger BDivBi = B.DividedBy(m_BModuli[i]);
		for (uint32_t j = 0; j<m_BDivBiModqTable[i].size(); j++)
		{
			BigInteger BDivBiModqj = BDivBi.Mod(moduli[j]);
			m_BDivBiModqTable[i][j] = BDivBiModqj.ConvertToInt();
			m_BDivBiModqPreconTable[i][j] = m_BDivBiModqTable[i][j].PrepModMulPreconNTL(moduli[j]);
		}
	}

	// Populate B/Bi mod msk
	m_BDivBiModmskTable.resize(m_numB);
	m_BDivBiModmskPreconTable.resize(m_numB);

	for (uint32_t i = 0; i < m_BDivBiModmskTable.size(); i++)
	{
		BigInteger BDivBi = B.DividedBy(m_BModuli[i]);
		m_BDivBiModmskTable[i] = (BDivBi.Mod(m_msk)).ConvertToInt();
		m_BDivBiModmskPreconTable[i] = m_BDivBiModmskTable[i].PrepModMulPreconNTL(m_msk);
	}

	// Populate B^-1 mod msk
	m_BInvModmsk = (B.ModInverse(m_msk)).ConvertToInt();
	m_BInvModmskPrecon = m_BInvModmsk.PrepModMulPreconNTL( m_msk );

	// Populate B mod qi
	m_BModqiTable.resize(m_numq);
	m_BModqiPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_BModqiTable.size(); i++)
	{
		m_BModqiTable[i] = (B.Mod( moduli[i] )).ConvertToInt();
		m_BModqiPreconTable[i] = m_BModqiTable[i].PrepModMulPreconNTL( moduli[i] );
	}

	// Priniting out for debugging
#ifdef BFVrns_APPROXIMATE_DEBUG
	std::cout << "numq: " << m_numq << endl;
	std::cout << "numB: " << m_numB << endl;

	std::cout << "B: " << B << endl;

	cout << "{q}: ";
	PrintSTDVector( moduli );
	cout << "{qRoots}: ";
	PrintSTDVector( roots );

	cout << "msk: " << m_msk << endl;
	cout << "mtilde: " << m_mtilde << endl;

	cout << "{Bsk}: ";
	PrintSTDVector( m_BskModuli );
	cout << "{BskRoots}: ";
	PrintSTDVector( m_BskRoots );

	cout << "{Bskmtilde}: ";
	PrintSTDVector( m_BskmtildeModuli );



	cout << "{(q/qi)^-1 mod qi}: ";
	PrintSTDVector( m_qDivqiModqiTable );

	cout << "{q/qi mod Bj (mat)}: \n";
	PrintSTDMat( m_qDivqiModBskmtildeTable );

	cout << "{mtilde*(q/qi)^-1 mod qi}: ";
	PrintSTDVector( m_mtildeqDivqiTable );

	cout << "-1/q mod mtilde: " << m_negqInvModmtilde << endl;

	cout << "{q mod Bski}: ";
	PrintSTDVector( m_qModBskiTable );

	cout << "{mtilde^-1 mod Bski}: ";
	PrintSTDVector( m_mtildeInvModBskiTable );

	cout << "{q^-1 mod Bski}: ";
	PrintSTDVector( m_qInvModBskiTable );

	cout << "{(B/Bi)^-1 mod Bi}: ";
	PrintSTDVector( m_BDivBiModBiTable );

	cout << "{B/Bi mod qj table (mat)}: \n";
	PrintSTDMat( m_BDivBiModqTable );

	cout << "{B/Bi mod msk}: ";
	PrintSTDVector( m_BDivBiModmskTable );

	cout << "B^-1 mod msk: " << m_BInvModmsk << endl;

	cout << "{B mod qi}: ";
	PrintSTDVector( m_BModqiTable );
#endif


	// Populate Decrns lookup tables
	// choose gamma
	m_gamma = NextPrime<NativeInteger>(m_mtilde, 2 * n);

	m_gammaInvModt = m_gamma.ModInverse(t.ConvertToInt());
	m_gammaInvModtPrecon = m_gammaInvModt.PrepModMulPreconNTL( t.ConvertToInt() );

	BigInteger negqModt = ((t-1) * q.ModInverse(t));
	BigInteger negqModgamma = ((m_gamma-1) * q.ModInverse(m_gamma));
	m_negqInvModtgammaTable.resize(2);
	m_negqInvModtgammaPreconTable.resize(2);

	m_negqInvModtgammaTable[0] = negqModt.Mod(t).ConvertToInt();
	m_negqInvModtgammaPreconTable[0] = m_negqInvModtgammaTable[0].PrepModMulPreconNTL( t.ConvertToInt() );

	m_negqInvModtgammaTable[1] = negqModgamma.Mod(m_gamma).ConvertToInt();
	m_negqInvModtgammaPreconTable[1] = m_negqInvModtgammaTable[1].PrepModMulPreconNTL(m_gamma);

	// Populate q/qi mod mj table where mj \in {t U gamma}
	m_qDivqiModtgammaTable.resize(m_numq);
	m_qDivqiModtgammaPreconTable.resize(m_numq);
	for (uint32_t i = 0; i < m_qDivqiModtgammaTable.size(); i++)
	{
		m_qDivqiModtgammaTable[i].resize(2);
		m_qDivqiModtgammaPreconTable[i].resize(2);

		BigInteger qDivqi = q.DividedBy(moduli[i]);

		BigInteger qDivqiModt = qDivqi.Mod(t);
		m_qDivqiModtgammaTable[i][0] = qDivqiModt.ConvertToInt();
		m_qDivqiModtgammaPreconTable[i][0] = m_qDivqiModtgammaTable[i][0].PrepModMulPreconNTL( t.ConvertToInt() );

		BigInteger qDivqiModgamma = qDivqi.Mod(m_gamma);
		m_qDivqiModtgammaTable[i][1] = qDivqiModgamma.ConvertToInt();
		m_qDivqiModtgammaPreconTable[i][1] = m_qDivqiModtgammaTable[i][1].PrepModMulPreconNTL( m_gamma );

	}

	// populate (t*gamma*q/qi)^-1 mod qi
	m_tgammaqDivqiModqiTable.resize( m_numq );
	m_tgammaqDivqiModqiPreconTable.resize(m_numq);

	for (uint32_t i = 0; i < m_tgammaqDivqiModqiTable.size(); i++)
	{
		BigInteger qDivqi = q.DividedBy(moduli[i]);
		qDivqi = qDivqi.ModInverse( moduli[i] );
		BigInteger gammaqDivqi = (qDivqi*m_gamma) % moduli[i];
		BigInteger tgammaqDivqi = (gammaqDivqi*t) % moduli[i];
		m_tgammaqDivqiModqiTable[i] = tgammaqDivqi.ConvertToInt();
		m_tgammaqDivqiModqiPreconTable[i] = m_tgammaqDivqiModqiTable[i].PrepModMulPreconNTL( moduli[i] );
	}

#ifdef BFVrns_APPROXIMATE_DEBUG
	cout << "gamma: " << m_gamma << endl;

	cout << "gamma^-1 mod t: " << m_gammaInvModt << endl;

	cout << "-1/q mod (t U gamma): ";
	PrintSTDVector( m_negqInvModtgammaTable );

	cout << "(q/qi) mod (t U gamma): ";
	PrintSTDMat( m_qDivqiModtgammaTable );

	cout << "t*gamma*(q/qi)^-1 mod qi: ";
	PrintSTDVector( m_tgammaqDivqiModqiTable );
#endif


	return true;
}

// Parameter generation for BFV-RNS
template <>
bool LPAlgorithmParamsGenBFVrnsApproximate<DCRTPoly>::ParamsGen(shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams, int32_t evalAddCount,
	int32_t evalMultCount, int32_t keySwitchCount, size_t dcrtBits) const
{

	if (!cryptoParams)
		PALISADE_THROW(not_available_error, "No crypto parameters are supplied to BFVrnsApproximate ParamsGen");

	if ((dcrtBits < 30) || (dcrtBits > 60))
		PALISADE_THROW(math_error, "BFVrnsApproximate.ParamsGen: Number of bits in CRT moduli should be in the range from 30 to 60");

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsBFVrnsApproximate = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(cryptoParams);

	double sigma = cryptoParamsBFVrnsApproximate->GetDistributionParameter();
	double alpha = cryptoParamsBFVrnsApproximate->GetAssuranceMeasure();
	double hermiteFactor = cryptoParamsBFVrnsApproximate->GetSecurityLevel();
	double p = cryptoParamsBFVrnsApproximate->GetPlaintextModulus();
	uint32_t relinWindow = cryptoParamsBFVrnsApproximate->GetRelinWindow();

	//Bound of the Gaussian error polynomial
	double Berr = sigma*sqrt(alpha);

	//Bound of the key polynomial
	double Bkey;

	//supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParamsBFVrnsApproximate->GetMode() == RLWE)
		Bkey = sigma*sqrt(alpha);
	else
		Bkey = 1;

	//expansion factor delta
	auto delta = [](uint32_t n) -> double { return sqrt(n); };

	//norm of fresh ciphertext polynomial
	auto Vnorm = [&](uint32_t n) -> double { return Berr*(1+2*delta(n)*Bkey);  };

	//RLWE security constraint
	auto nRLWE = [&](double q) -> double { return log2(q / sigma) / (4 * log2(hermiteFactor));  };

	//initial values
	uint32_t n = 512;
	double q = 0;

	//only public key encryption and EvalAdd (optional when evalAddCount = 0) operations are supported
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	if ((evalMultCount == 0) && (keySwitchCount == 0)) {

		//Correctness constraint
		auto qBFV = [&](uint32_t n) -> double { return p*(2*((evalAddCount+1)*Vnorm(n) + evalAddCount*p) + p);  };

		//initial value
		q = qBFV(n);

		while (nRLWE(q) > n) {
			n = 2 * n;
			q = qBFV(n);
		}

		// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

		int32_t k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);

		double qCeil = pow(2,k*dcrtBits);

		while (nRLWE(qCeil) > n) {
			n = 2 * n;
			q = qBFV(n);
			k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);
			qCeil = pow(2,k*dcrtBits);
		}

	}
	// this case supports re-encryption and automorphism w/o any other operations
	else if ((evalMultCount == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {

		//base for relinearization
		double w;
		if (relinWindow == 0)
			w = pow(2, dcrtBits);
		else
			w = pow(2, relinWindow);

		//Correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2*(Vnorm(n) + keySwitchCount*delta(n)*(floor(log2(qPrev) / dcrtBits) + 1)*w*Berr) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theortically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

			// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

			int32_t k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);

			double qCeil = pow(2,k*dcrtBits);
			qPrev = qCeil;

			while (nRLWE(qCeil) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);
				qCeil = pow(2,k*dcrtBits);
				qPrev = qCeil;
			}

		}

	}
	//Only EvalMult operations are used in the correctness constraint
	//the correctness constraint from section 3.5 of https://eprint.iacr.org/2014/062.pdf is used
	else if ((evalAddCount == 0) && (evalMultCount > 0) && (keySwitchCount == 0))
	{

		//base for relinearization
		double w;
		if (relinWindow == 0)
			w = pow(2, dcrtBits);
		else
			w = pow(2, relinWindow);

		//function used in the EvalMult constraint
		auto epsilon1 = [&](uint32_t n) -> double { return 4 / (delta(n)*Bkey);  };

		//function used in the EvalMult constraint
		auto C1 = [&](uint32_t n) -> double { return (1 + epsilon1(n))*delta(n)*delta(n)*p*Bkey;  };

		//function used in the EvalMult constraint
		auto C2 = [&](uint32_t n, double qPrev) -> double { return delta(n)*delta(n)*Bkey*(Bkey + p*p) + delta(n)*(floor(log2(qPrev) / dcrtBits) + 1)*w*Berr;  };

		//main correctness constraint
		auto qBFV = [&](uint32_t n, double qPrev) -> double { return p*(2 * (pow(C1(n), evalMultCount)*Vnorm(n) + evalMultCount*pow(C1(n), evalMultCount - 1)*C2(n, qPrev)) + p);  };

		//initial values
		double qPrev = 1e6;
		q = qBFV(n, qPrev);
		qPrev = q;

		//this "while" condition is needed in case the iterative solution for q
		//changes the requirement for n, which is rare but still theoretically possible
		while (nRLWE(q) > n) {

			while (nRLWE(q) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				qPrev = q;
			}

			q = qBFV(n, qPrev);

			while (std::abs(q - qPrev) > 0.001*q) {
				qPrev = q;
				q = qBFV(n, qPrev);
			}

			// this code updates n and q to account for the discrete size of CRT moduli = dcrtBits

			int32_t k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);

			double qCeil = pow(2,k*dcrtBits);
			qPrev = qCeil;

			while (nRLWE(qCeil) > n) {
				n = 2 * n;
				q = qBFV(n, qPrev);
				k = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);
				qCeil = pow(2,k*dcrtBits);
				qPrev = qCeil;
			}

		}

	}

	size_t size = ceil((ceil(log2(q)) + 1.0) / (double)dcrtBits);

	vector<NativeInteger> moduli(size);
	vector<NativeInteger> roots(size);

	//makes sure the first integer is less than 2^60-1 to take advangate of NTL optimizations
	NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);
	firstInteger -= (int64_t)(2*n)*((int64_t)(1)<<(dcrtBits/3));
	moduli[0] = NextPrime<NativeInteger>(firstInteger, 2 * n);
	roots[0] = RootOfUnity<NativeInteger>(2 * n, moduli[0]);

	for (size_t i = 1; i < size; i++)
	{
		moduli[i] = NextPrime<NativeInteger>(moduli[i-1], 2 * n);
		roots[i] = RootOfUnity<NativeInteger>(2 * n, moduli[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(2 * n, moduli, roots));

	ChineseRemainderTransformFTT<NativeInteger,NativeVector>::PreCompute(roots,2*n,moduli);

	cryptoParamsBFVrnsApproximate->SetElementParams(params);

	return cryptoParamsBFVrnsApproximate->PrecomputeCRTTables();

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsApproximate<DCRTPoly>::Encrypt(const LPPublicKey<DCRTPoly> publicKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(publicKey) );

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();
/*
	const std::vector<NativeInteger> &dTable = cryptoParams->GetCRTDeltaTable();
	Poly dTable2(elementParams, EVALUATION, true);
	for( size_t i=0; i<dTable.size(); i++ )
		dTable2.at(i) = Poly::Integer(dTable.at(i).ConvertToInt());
	DCRTPoly deltaTable( dTable2, elementParams );
*/

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::TugType tug;

	const DCRTPoly &p0 = publicKey->GetPublicElements().at(0);
	const DCRTPoly &p1 = publicKey->GetPublicElements().at(1);

	DCRTPoly u;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		u = DCRTPoly(dgg, elementParams, Format::EVALUATION);
	else
		u = DCRTPoly(tug, elementParams, Format::EVALUATION);

	DCRTPoly e1(dgg, elementParams, Format::EVALUATION);
	DCRTPoly e2(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(elementParams);
	DCRTPoly c1(elementParams);

	c0 = p0*u + e1 + ptxt.Times(deltaTable);

	c1 = p1*u + e2;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

// Exact BFVrns
//template <>
//DecryptResult LPAlgorithmBFVrnsApproximate<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
//		const Ciphertext<DCRTPoly> ciphertext,
//		NativePoly *plaintext) const
//{
//	//TimeVar t_total;
//
//	//TIC(t_total);
//
//	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams =
//			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(privateKey->GetCryptoParameters());
//	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();
//
//	const std::vector<DCRTPoly> &c = ciphertext->GetElements();
//
//	const DCRTPoly &s = privateKey->GetPrivateElement();
//	DCRTPoly sPower = s;
//
//	DCRTPoly b = c[0];
//	if(b.GetFormat() == Format::COEFFICIENT)
//		b.SwitchFormat();
//
//	DCRTPoly cTemp;
//	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
//		cTemp = c[i];
//		if(cTemp.GetFormat() == Format::COEFFICIENT)
//			cTemp.SwitchFormat();
//
//		b += sPower*cTemp;
//		sPower *= s;
//	}
//
//	// Converts back to coefficient representation
//	b.SwitchFormat();
//
//	auto &p = cryptoParams->GetPlaintextModulus();
//
//	const std::vector<double> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
//	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();
//	const std::vector<NativeInteger> &invPreconTable = cryptoParams->GetCRTDecryptionIntPreconTable();
//
//	// this is the resulting vector of coefficients;
//	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable);
//
//	//std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" << std::endl;
//
//	return DecryptResult(plaintext->GetLength());
//
//}



 // Approximate BFVrns
template <>
DecryptResult LPAlgorithmBFVrnsApproximate<DCRTPoly>::Decrypt(const LPPrivateKey<DCRTPoly> privateKey,
		const Ciphertext<DCRTPoly> ciphertext,
		NativePoly *plaintext) const
{
	//TimeVar t_total;

	//TIC(t_total);

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsBFVrnsApproximate =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(privateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrnsApproximate->GetElementParams();

	const std::vector<DCRTPoly> &c = ciphertext->GetElements();

	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly sPower = s;

	DCRTPoly b = c[0];
	if(b.GetFormat() == Format::COEFFICIENT)
		b.SwitchFormat();

	DCRTPoly cTemp;
	for(size_t i=1; i<=ciphertext->GetDepth(); i++){
		cTemp = c[i];
		if(cTemp.GetFormat() == Format::COEFFICIENT)
			cTemp.SwitchFormat();

		b += sPower*cTemp;
		sPower *= s;
	}

	// Converts back to coefficient representation
	b.SwitchFormat();

	auto &t = cryptoParamsBFVrnsApproximate->GetPlaintextModulus();

	// Invoke approximate DecRNS

	const std::vector<NativeInteger> paramsqModuliTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsqModuli();
	const NativeInteger paramsgamma = cryptoParamsBFVrnsApproximate->GetDCRTParamsgamma();
	const NativeInteger paramsgammaInvModt = cryptoParamsBFVrnsApproximate->GetDCRTParamsgammaInvModt();
	const NativeInteger paramsgammaInvModtPrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsgammaInvModtPrecon();
	const std::vector<NativeInteger> paramsnegqInvModtgammaTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsnegqInvModtgammaTable();
	const std::vector<NativeInteger> paramsnegqInvModtgammaPreconTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsnegqInvModtgammaPreconTable();
	const std::vector<NativeInteger> paramstgammaqDivqiModqiTable = cryptoParamsBFVrnsApproximate->GetDCRTParamstgammaqDivqiModqiTable();
	const std::vector<NativeInteger> paramstgammaqDivqiModqiPreconTable = cryptoParamsBFVrnsApproximate->GetDCRTParamstgammaqDivqiModqiPreconTable();
	const std::vector<std::vector<NativeInteger>> paramsqDivqiModtgammaTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsqDivqiModtgammaTable();
	const std::vector<std::vector<NativeInteger>> paramsqDivqiModtgammaPreconTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsqDivqiModtgammaPreconTable();



	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(paramsqModuliTable,
			paramsgamma,
			t,
			paramsgammaInvModt,
			paramsgammaInvModtPrecon,
			paramsnegqInvModtgammaTable,
			paramsnegqInvModtgammaPreconTable,
			paramstgammaqDivqiModqiTable,
			paramstgammaqDivqiModqiPreconTable,
			paramsqDivqiModtgammaTable,
			paramsqDivqiModtgammaPreconTable);

	//std::cout << "Decryption time (internal): " << TOC_US(t_total) << " us" << std::endl;

	return DecryptResult(plaintext->GetLength());

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmBFVrnsApproximate<DCRTPoly>::Encrypt(const LPPrivateKey<DCRTPoly> privateKey,
		DCRTPoly ptxt) const
{
	Ciphertext<DCRTPoly> ciphertext( new CiphertextImpl<DCRTPoly>(privateKey) );

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(privateKey->GetCryptoParameters());

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	ptxt.SwitchFormat();

	const typename DCRTPoly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	DCRTPoly a(dug, elementParams, Format::EVALUATION);
	const DCRTPoly &s = privateKey->GetPrivateElement();
	DCRTPoly e(dgg, elementParams, Format::EVALUATION);

	DCRTPoly c0(a*s + e + ptxt.Times(deltaTable));
	DCRTPoly c1(elementParams, Format::EVALUATION, true);
	c1 -= a;

	ciphertext->SetElements({ c0, c1 });

	return ciphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::EvalAdd(const Ciphertext<DCRTPoly> ciphertext,
	const Plaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<DCRTPoly>().SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetEncodedElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] + ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::EvalSub(const Ciphertext<DCRTPoly> ciphertext,
	const Plaintext plaintext) const{

	Ciphertext<DCRTPoly> newCiphertext = ciphertext->CloneEmpty();
	newCiphertext->SetDepth(ciphertext->GetDepth());

	const std::vector<DCRTPoly> &cipherTextElements = ciphertext->GetElements();

	plaintext->GetEncodedElement<DCRTPoly>().SetFormat(EVALUATION);
	const DCRTPoly& ptElement = plaintext->GetEncodedElement<DCRTPoly>();

	std::vector<DCRTPoly> c(cipherTextElements.size());

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ciphertext->GetCryptoParameters());

    const std::vector<NativeInteger> &deltaTable = cryptoParams->GetCRTDeltaTable();

	c[0] = cipherTextElements[0] - ptElement.Times(deltaTable);

	for(size_t i=1; i<cipherTextElements.size(); i++) {
			c[i] = cipherTextElements[i];
	}

	newCiphertext->SetElements(c);

	return newCiphertext;

}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::EvalMult(const Ciphertext<DCRTPoly> ciphertext1,
	const Ciphertext<DCRTPoly> ciphertext2) const {

	if (!(ciphertext1->GetCryptoParameters() == ciphertext2->GetCryptoParameters())) {
		std::string errMsg = "LPAlgorithmSHEBFVrnsApproximate::EvalMult crypto parameters are not the same";
		throw std::runtime_error(errMsg);
	}

	Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsBFVrnsApproximate =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ciphertext1->GetCryptoContext()->GetCryptoParameters());
	//Check if the multiplication supports the depth
	if ( (ciphertext1->GetDepth() + ciphertext2->GetDepth()) > cryptoParamsBFVrnsApproximate->GetMaxDepth() ) {
			std::string errMsg = "LPAlgorithmSHEBFVrnsApproximate::EvalMult multiplicative depth is not supported";
			throw std::runtime_error(errMsg);
	}

	//Get the ciphertext elements
	std::vector<DCRTPoly> cipherText1Elements = ciphertext1->GetElements();
	std::vector<DCRTPoly> cipherText2Elements = ciphertext2->GetElements();

	size_t cipherText1ElementsSize = cipherText1Elements.size();
	size_t cipherText2ElementsSize = cipherText2Elements.size();
	size_t cipherTextRElementsSize = cipherText1ElementsSize + cipherText2ElementsSize - 1;

	std::vector<DCRTPoly> c(cipherTextRElementsSize);

	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsBFVrnsApproximate->GetElementParams();
	const shared_ptr<ILDCRTParams<BigInteger>> paramsBsk = cryptoParamsBFVrnsApproximate->GetDCRTParamsBsk();

	const std::vector<NativeInteger> paramsqModuli = cryptoParamsBFVrnsApproximate->GetDCRTParamsqModuli();
	const std::vector<NativeInteger> paramsBskModuli = cryptoParamsBFVrnsApproximate->GetDCRTParamsBskModuli();
	const std::vector<NativeInteger> paramsBskmtildeModuli = cryptoParamsBFVrnsApproximate->GetDCRTParamsBskmtildeModuli();
	const std::vector<NativeInteger> paramsmtildeqDivqiModqi = cryptoParamsBFVrnsApproximate->GetDCRTParamsmtildeqDivqiModqi();
	const std::vector<NativeInteger> paramsmtildeqDivqiModqiPrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsmtildeqDivqiModqiPrecon();
	const std::vector<std::vector<NativeInteger>> paramsqDivqiModBskmtilde = cryptoParamsBFVrnsApproximate->GetDCRTParamsqDivqiModBskmtilde();
	const std::vector<std::vector<NativeInteger>> paramsqDivqiModBskmtildePrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsqDivqiModBskmtildePrecon();
	const std::vector<NativeInteger> paramsqModBski = cryptoParamsBFVrnsApproximate->GetDCRTParamsqModBski();
	const std::vector<NativeInteger> paramsqModBskiPrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsqModBskiPrecon();
	const NativeInteger paramsnegqInvModmtilde = cryptoParamsBFVrnsApproximate->GetDCRTParamsnegqInvModmtilde();
	const NativeInteger paramsnegqInvModmtildePrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsnegqInvModmtildePrecon();
	const std::vector<NativeInteger> paramsmtildeInvModBskiTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsmtildeInvModBskiTable();
	const std::vector<NativeInteger> paramsmtildeInvModBskiPreconTable = cryptoParamsBFVrnsApproximate->GetDCRTParamsmtildeInvModBskiPreconTable();

	// Expands the CRT basis to q*Bsk; Outputs the polynomials in coeff representation



#ifdef BFVrns_APPROXIMATE_DEBUG
	Ciphertext<DCRTPoly> cp_ciphertext1 = ciphertext1;
	Ciphertext<DCRTPoly> cp_ciphertext2 = ciphertext2;
	std::vector<DCRTPoly> cp_cipherText1Elements = cp_ciphertext1->GetElements();
	std::vector<DCRTPoly> cp_cipherText2Elements = cp_ciphertext2->GetElements();

	size_t cp_cipherText1ElementsSize = cp_cipherText1Elements.size();
	size_t cp_cipherText2ElementsSize = cp_cipherText2Elements.size();

	for (size_t i = 0; i<cp_cipherText1ElementsSize; i++)
	{
		if ( cp_cipherText1Elements[i].GetFormat() == EVALUATION )
			cp_cipherText1Elements[i].SwitchFormat();

		if ( cp_cipherText2Elements[i].GetFormat() == EVALUATION )
			cp_cipherText2Elements[i].SwitchFormat();
	}
	cout << "\n ------------------------------------------------- \n";
	cout << "                  Input ciphertexts                  \n";
	cout << " --------------------------------------------------- \n";
	cout << "ct00Coeff = {" << cp_cipherText1Elements[0].CRTInterpolate() << "};" << endl;
	cout << "ct01Coeff = {" << cp_cipherText1Elements[1].CRTInterpolate() << "};" << endl;

	cout << "ct10Coeff = {" << cp_cipherText2Elements[0].CRTInterpolate() << "};" << endl;
	cout << "ct11Coeff = {" << cp_cipherText2Elements[1].CRTInterpolate() << "};" << endl;


	for(size_t i=0; i<cp_cipherText1ElementsSize; i++)
	{
		cp_cipherText1Elements[i].FastBaseConvqToBskMontgomery(paramsBsk, paramsqModuli, paramsBskmtildeModuli, paramsmtildeqDivqiModqi, paramsqDivqiModBskmtilde, paramsqModBski, paramsnegqInvModmtilde, paramsmtildeInvModBskiTable);
//		if (cp_cipherText1Elements[i].GetFormat() == COEFFICIENT) {
//			cp_cipherText1Elements[i].SwitchFormat();
//		}
	}

	for(size_t i=0; i<cp_cipherText2ElementsSize; i++)
	{
		cp_cipherText2Elements[i].FastBaseConvqToBskMontgomery(paramsBsk, paramsqModuli, paramsBskmtildeModuli, paramsmtildeqDivqiModqi, paramsqDivqiModBskmtilde, paramsqModBski, paramsnegqInvModmtilde, paramsmtildeInvModBskiTable);
//		if (cp_cipherText2Elements[i].GetFormat() == COEFFICIENT) {
//			cp_cipherText2Elements[i].SwitchFormat();
//		}
	}

	cout << "\n ------------------------------------------------- \n";
	cout << "        Extended ciphertexts in base q U Bsk         \n";
	cout << " --------------------------------------------------- \n";
	cout << "ct00Coeff = {" << cp_cipherText1Elements[0] << "};" << endl;
	cout << "ct01Coeff = {" << cp_cipherText1Elements[1] << "};" << endl;

	cout << "ct10Coeff = {" << cp_cipherText2Elements[0] << "};" << endl;
	cout << "ct11Coeff = {" << cp_cipherText2Elements[1] << "};" << endl;

#endif

	for(size_t i=0; i<cipherText1ElementsSize; i++)
	{
		cipherText1Elements[i].FastBaseConvqToBskMontgomery(paramsBsk,
				paramsqModuli,
				paramsBskmtildeModuli,
				paramsmtildeqDivqiModqi,
				paramsmtildeqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqDivqiModBskmtildePrecon,
				paramsqModBski,
				paramsqModBskiPrecon,
				paramsnegqInvModmtilde,
				paramsnegqInvModmtildePrecon,
				paramsmtildeInvModBskiTable,
				paramsmtildeInvModBskiPreconTable);
		if (cipherText1Elements[i].GetFormat() == COEFFICIENT) {
			cipherText1Elements[i].SwitchFormat();
		}
	}

	for(size_t i=0; i<cipherText2ElementsSize; i++)
	{
		cipherText2Elements[i].FastBaseConvqToBskMontgomery(paramsBsk,
				paramsqModuli,
				paramsBskmtildeModuli,
				paramsmtildeqDivqiModqi,
				paramsmtildeqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqDivqiModBskmtildePrecon,
				paramsqModBski,
				paramsqModBskiPrecon,
				paramsnegqInvModmtilde,
				paramsnegqInvModmtildePrecon,
				paramsmtildeInvModBskiTable,
				paramsmtildeInvModBskiPreconTable);
		if (cipherText2Elements[i].GetFormat() == COEFFICIENT) {
			cipherText2Elements[i].SwitchFormat();
		}
	}

	// Performs the multiplication itself
	// TODO this can be improved by using Karatsuba multiplication algorithm (3 muls instead of 4)

	bool *isFirstAdd = new bool[cipherTextRElementsSize];
	std::fill_n(isFirstAdd, cipherTextRElementsSize, true);

	for(size_t i=0; i<cipherText1ElementsSize; i++){
		for(size_t j=0; j<cipherText2ElementsSize; j++){

			if(isFirstAdd[i+j] == true){
				c[i+j] = cipherText1Elements[i] * cipherText2Elements[j];
				isFirstAdd[i+j] = false;
			}
			else{
				c[i+j] += cipherText1Elements[i] * cipherText2Elements[j];
			}
		}
	}

	delete []isFirstAdd;

#ifdef BFVrns_APPROXIMATE_DEBUG
	cout << "\n ------------------------------------------------- \n";
	cout << "            c0, c1, c2 in basis q U Bsk              \n";
	cout << " --------------------------------------------------- \n";
#endif

	// perfrom RNS approximate Flooring
	const NativeInteger paramsPlaintextModulus = cryptoParamsBFVrnsApproximate->GetPlaintextModulus();
	const NativeInteger paramsPlaintextModulusPrecon = cryptoParamsBFVrnsApproximate->GetPlaintextModulusPrecon();
	const std::vector<NativeInteger> paramstqDivqiModqi = cryptoParamsBFVrnsApproximate->GetDCRTParamstqDivqiModqiTable();
	const std::vector<NativeInteger> paramstqDivqiModqiPrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamstqDivqiModqiPreconTable();
	const std::vector<NativeInteger> paramsqInvModBi = cryptoParamsBFVrnsApproximate->GetDCRTParamsqInvModBiTable();
	const std::vector<NativeInteger> paramsqInvModBiPrecon = cryptoParamsBFVrnsApproximate->GetDCRTParamsqInvModBiPreconTable();


	// perform FastBaseConvSK
	const std::vector<NativeInteger> paramsBDivBiModBi = cryptoParamsBFVrnsApproximate->GetBDivBiModBi();
	const std::vector<NativeInteger> paramsBDivBiModBiPrecon = cryptoParamsBFVrnsApproximate->GetBDivBiModBiPrecon();
	const std::vector<NativeInteger> paramsBDivBiModmsk = cryptoParamsBFVrnsApproximate->GetBDivBiModmsk();
	const std::vector<NativeInteger> paramsBDivBiModmskPrecon = cryptoParamsBFVrnsApproximate->GetBDivBiModmskPrecon();
	const NativeInteger paramsBInvModmsk = cryptoParamsBFVrnsApproximate->GetBInvModmsk();
	const NativeInteger paramsBInvModmskPrecon = cryptoParamsBFVrnsApproximate->GetBInvModmskPrecon();
	const std::vector<std::vector<NativeInteger>> paramsBDivBiModqj = cryptoParamsBFVrnsApproximate->GetBDivBiModqj();
	const std::vector<std::vector<NativeInteger>> paramsBDivBiModqjPrecon = cryptoParamsBFVrnsApproximate->GetBDivBiModqjPrecon();
	const std::vector<NativeInteger> paramsBModqi = cryptoParamsBFVrnsApproximate->GetBModqi();
	const std::vector<NativeInteger> paramsBModqiPrecon = cryptoParamsBFVrnsApproximate->GetBModqiPrecon();

	for(size_t i=0; i<cipherTextRElementsSize; i++){
		//converts to coefficient representation before rounding
		c[i].SwitchFormat();
		// Performs the scaling by t/q followed by rounding; the result is in the CRT basis Bsk
		c[i].FastRNSFloorq(paramsPlaintextModulus,
				paramsPlaintextModulusPrecon,
				paramsqModuli,
				paramsBskModuli,
				paramstqDivqiModqi,
				paramstqDivqiModqiPrecon,
				paramsqDivqiModBskmtilde,
				paramsqDivqiModBskmtildePrecon,
				paramsqInvModBi,
				paramsqInvModBiPrecon);
		// Converts from the CRT basis Bsk to q
		c[i].FastBaseConvSK(paramsqModuli,
				paramsBskModuli,
				paramsBDivBiModBi,
				paramsBDivBiModBiPrecon,
				paramsBDivBiModmsk,
				paramsBDivBiModmskPrecon,
				paramsBInvModmsk,
				paramsBInvModmskPrecon,
				paramsBDivBiModqj,
				paramsBDivBiModqjPrecon,
				paramsBModqi,
				paramsBModqiPrecon);
	}

	newCiphertext->SetElements(c);
	newCiphertext->SetDepth((ciphertext1->GetDepth() + ciphertext2->GetDepth()));

	return newCiphertext;

}

template <>
LPEvalKey<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::KeySwitchGen(const LPPrivateKey<DCRTPoly> originalPrivateKey,
	const LPPrivateKey<DCRTPoly> newPrivateKey) const {

	LPEvalKeyRelin<DCRTPoly> ek(new LPEvalKeyRelinImpl<DCRTPoly>(newPrivateKey->GetCryptoContext()));

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(newPrivateKey->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParamsLWE->GetElementParams();
	const DCRTPoly &s = newPrivateKey->GetPrivateElement();

	const typename DCRTPoly::DggType &dgg = cryptoParamsLWE->GetDiscreteGaussianGenerator();
	typename DCRTPoly::DugType dug;

	const DCRTPoly &oldKey = originalPrivateKey->GetPrivateElement();

	std::vector<DCRTPoly> evalKeyElements;
	std::vector<DCRTPoly> evalKeyElementsGenerated;

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	for (usint i = 0; i < oldKey.GetNumOfElements(); i++)
	{

		if (relinWindow>0)
		{
			vector<typename DCRTPoly::PolyType> decomposedKeyElements = oldKey.GetElementAtIndex(i).PowersOfBase(relinWindow);

			for (size_t k = 0; k < decomposedKeyElements.size(); k++)
			{

				// Creates an element with all zeroes
				DCRTPoly filtered(elementParams,EVALUATION,true);

				filtered.SetElementAtIndex(i,decomposedKeyElements[k]);

				// Generate a_i vectors
				DCRTPoly a(dug, elementParams, Format::EVALUATION);
				evalKeyElementsGenerated.push_back(a);

				// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
				DCRTPoly e(dgg, elementParams, Format::EVALUATION);
				evalKeyElements.push_back(filtered - (a*s + e));
			}
		}
		else
		{

			// Creates an element with all zeroes
			DCRTPoly filtered(elementParams,EVALUATION,true);

			filtered.SetElementAtIndex(i,oldKey.GetElementAtIndex(i));

			// Generate a_i vectors
			DCRTPoly a(dug, elementParams, Format::EVALUATION);
			evalKeyElementsGenerated.push_back(a);

			// Generate a_i * s + e - [oldKey]_qi [(q/qi)^{-1}]_qi (q/qi)
			DCRTPoly e(dgg, elementParams, Format::EVALUATION);
			evalKeyElements.push_back(filtered - (a*s + e));
		}

	}

	ek->SetAVector(std::move(evalKeyElements));
	ek->SetBVector(std::move(evalKeyElementsGenerated));

	return ek;

}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::KeySwitch(const LPEvalKey<DCRTPoly> ek,
	const Ciphertext<DCRTPoly> cipherText) const
{

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ek->GetCryptoParameters());

	LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek);

	const std::vector<DCRTPoly> &c = cipherText->GetElements();

	const std::vector<DCRTPoly> &b = evalKey->GetAVector();
	const std::vector<DCRTPoly> &a = evalKey->GetBVector();

	uint32_t relinWindow = cryptoParamsLWE->GetRelinWindow();

	std::vector<DCRTPoly> digitsC2;

	DCRTPoly ct0(c[0]);

	//in the case of EvalMult, c[0] is initially in coefficient format and needs to be switched to evaluation format
	if (c.size() > 2)
		ct0.SwitchFormat();

	DCRTPoly ct1;

	if (c.size() == 2) //case of PRE or automorphism
	{
		digitsC2 = c[1].CRTDecompose(relinWindow);
		ct1 = digitsC2[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC2 = c[2].CRTDecompose(relinWindow);
		ct1 = c[1];
		//Convert ct1 to evaluation representation
		ct1.SwitchFormat();
		ct1 += digitsC2[0] * a[0];

	}

	ct0 += digitsC2[0] * b[0];

	for (usint i = 1; i < digitsC2.size(); ++i)
	{
		ct0 += digitsC2[i] * b[i];
		ct1 += digitsC2[i] * a[i];
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;
}


template <>
Ciphertext<DCRTPoly> LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>::EvalMultAndRelinearize(const Ciphertext<DCRTPoly> ciphertext1,
	const Ciphertext<DCRTPoly> ciphertext2, const vector<LPEvalKey<DCRTPoly>> &ek) const{

	Ciphertext<DCRTPoly> cipherText = this->EvalMult(ciphertext1, ciphertext2);

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParamsLWE =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ek[0]->GetCryptoParameters());

	Ciphertext<DCRTPoly> newCiphertext = cipherText->CloneEmpty();

	std::vector<DCRTPoly> c = cipherText->GetElements();

	if(c[0].GetFormat() == Format::COEFFICIENT)
		for(size_t i=0; i<c.size(); i++)
			c[i].SwitchFormat();

	DCRTPoly ct0(c[0]);
	DCRTPoly ct1(c[1]);
	// Perform a keyswitching operation to result of the multiplication. It does it until it reaches to 2 elements.
	//TODO: Maybe we can change the number of keyswitching and terminate early. For instance; perform keyswitching until 4 elements left.
	for(size_t j = 0; j<=cipherText->GetDepth()-2; j++){
		size_t index = cipherText->GetDepth()-2-j;
		LPEvalKeyRelin<DCRTPoly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<DCRTPoly>>(ek[index]);

		const std::vector<DCRTPoly> &b = evalKey->GetAVector();
		const std::vector<DCRTPoly> &a = evalKey->GetBVector();

		std::vector<DCRTPoly> digitsC2 = c[index+2].CRTDecompose();

		for (usint i = 0; i < digitsC2.size(); ++i){
			ct0 += digitsC2[i] * b[i];
			ct1 += digitsC2[i] * a[i];
		}
	}

	newCiphertext->SetElements({ ct0, ct1 });

	return newCiphertext;

}

template <>
DecryptResult LPAlgorithmMultipartyBFVrnsApproximate<DCRTPoly>::MultipartyDecryptFusion(const vector<Ciphertext<DCRTPoly>>& ciphertextVec,
		NativePoly *plaintext) const
{

	const shared_ptr<LPCryptoParametersBFVrnsApproximate<DCRTPoly>> cryptoParams =
			std::dynamic_pointer_cast<LPCryptoParametersBFVrnsApproximate<DCRTPoly>>(ciphertextVec[0]->GetCryptoParameters());
	const shared_ptr<typename DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();

	const auto &p = cryptoParams->GetPlaintextModulus();

	const std::vector<DCRTPoly> &cElem = ciphertextVec[0]->GetElements();
	DCRTPoly b = cElem[0];

	size_t numCipher = ciphertextVec.size();
	for( size_t i = 1; i < numCipher; i++ ) {
		const std::vector<DCRTPoly> &c2 = ciphertextVec[i]->GetElements();
		b += c2[0];
	}

	const std::vector<QuadFloat> &lyamTable = cryptoParams->GetCRTDecryptionFloatTable();
	const std::vector<NativeInteger> &invTable = cryptoParams->GetCRTDecryptionIntTable();
	const std::vector<NativeInteger> &invPreconTable = cryptoParams->GetCRTDecryptionIntPreconTable();

	// this is the resulting vector of coefficients;
	*plaintext = b.ScaleAndRound(p,invTable,lyamTable,invPreconTable);;

	return DecryptResult(plaintext->GetLength());

}


template class LPCryptoParametersBFVrnsApproximate<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFVrnsApproximate<DCRTPoly>;
template class LPAlgorithmBFVrnsApproximate<DCRTPoly>;
template class LPAlgorithmSHEBFVrnsApproximate<DCRTPoly>;
template class LPAlgorithmMultipartyBFVrnsApproximate<DCRTPoly>;
template class LPAlgorithmParamsGenBFVrnsApproximate<DCRTPoly>;

}
