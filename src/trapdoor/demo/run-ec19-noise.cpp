#define PROFILE  //define this to enable PROFILELOG and TIC/TOC

#include "subgaussian/subgaussian.h"
#include "subgaussian/gsw.h"
#include "subgaussian/gsw.cpp"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

shared_ptr<Matrix<DCRTPoly>> InverseG(const Matrix<DCRTPoly> &A, usint base);

#define PROFILE

int main()
{

	usint n = 1024;   // cyclotomic order
	size_t kRes = 60;

	size_t depth = 2;

	usint base = 2;

	size_t size = 2;

	std::cout << "n: " << n << std::endl;

	//double sigma = SIGMA;

	std::vector<NativeInteger> moduli;
	std::vector<NativeInteger> roots_Of_Unity;

	//makes sure the first integer is less than 2^60-1 to take advangate of NTL optimizations
	NativeInteger firstInteger = FirstPrime<NativeInteger>(kRes, 2 * n);
	//firstInteger -= 2*n*((uint64_t)(1)<<40);
	firstInteger -= (int64_t)(2*n)*((int64_t)(1)<<(kRes/3));
	NativeInteger q = NextPrime<NativeInteger>(firstInteger, 2 * n);
	moduli.push_back(q);
	roots_Of_Unity.push_back(RootOfUnity<NativeInteger>(2 * n, moduli[0]));

	NativeInteger nextQ = q;
	for (size_t i = 1; i < size; i++) {
		nextQ = lbcrypto::NextPrime<NativeInteger>(nextQ, 2*n);
		NativeInteger nextRootOfUnity(RootOfUnity<NativeInteger>(2*n, nextQ));
		moduli.push_back(nextQ);
		roots_Of_Unity.push_back(nextRootOfUnity);
	}

	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(2*n, moduli, roots_Of_Unity));

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(roots_Of_Unity,2*n,moduli);

	std::cout << "k: " << ilDCRTParams->GetModulus().GetMSB() << std::endl;

	size_t digitCount = (long)ceil(log2(ilDCRTParams->GetParams()[0]->GetModulus().ConvertToDouble())/log2(base));
	size_t k = digitCount*ilDCRTParams->GetParams().size();

	std::cout << "digit count = " << digitCount << std::endl;
	std::cout << "k = " << k << std::endl;

	size_t m = k + 2;

	vector<LatticeSubgaussianUtility<NativeInteger>> util;

	for(size_t i = 0; i < moduli.size(); i++)
		util.push_back(LatticeSubgaussianUtility<NativeInteger>(base,moduli[i],digitCount));

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();
	DCRTPoly::BugType bug = DCRTPoly::BugType();

	auto zero_alloc = DCRTPoly::Allocator(ilDCRTParams, EVALUATION);
	auto uniform_alloc = DCRTPoly::MakeDiscreteUniformAllocator(ilDCRTParams, COEFFICIENT);
	auto gaussian_alloc = DCRTPoly::MakeDiscreteGaussianCoefficientAllocator(ilDCRTParams, EVALUATION, SIGMA);

	Matrix<DCRTPoly> E1(zero_alloc, 1, m, gaussian_alloc);
	Matrix<DCRTPoly> E2(zero_alloc, 1, m, gaussian_alloc);
	Matrix<DCRTPoly> A(zero_alloc, 1, m, uniform_alloc);

	for (size_t i = 0 ; i < depth; i++)
	{
		auto gInverse = InverseRingVectorDCRT(util,A,1);
		gInverse->SwitchFormat();
		E1 = E1*(*gInverse);

		auto temp = E1;
		temp.SwitchFormat();
		std::cout << "level: " << i+1 << "; norm: " << temp.Norm() << std::endl;
	}

	for (size_t i = 0 ; i < depth; i++)
	{
		auto gInverse = InverseG(A,base);
		//std::cerr << (*gInverse)(0,0).GetFormat() << std::endl;
		gInverse->SwitchFormat();
		E2 = E2*(*gInverse);

		auto temp = E2;
		temp.SwitchFormat();
		std::cout << "level: " << i+1 << "; norm: " << temp.Norm() << std::endl;
	}

	return 0;
}

shared_ptr<Matrix<DCRTPoly>> InverseG(const Matrix<DCRTPoly> &A, usint base) {

	usint n = A(0,0).GetRingDimension();

	size_t k = (long)ceil(log2(A(0,0).GetModulus().ConvertToDouble())/log2(base));

	usint m = A.GetCols();

	auto zero_alloc_poly = DCRTPoly::Allocator(A(0,0).GetParams(), COEFFICIENT);
	shared_ptr<Matrix<DCRTPoly>> psi(new Matrix<DCRTPoly>(zero_alloc_poly, m, m));

	for (size_t i = 0; i < A.GetCols(); i++)
	{
		Poly temp = A(0,i).CRTInterpolate();
		for (size_t j = 0; j < n; j++)
		{
			std::vector<int64_t> digits = *(GetDigits(temp[j],base,k));
			for (size_t v=0; v < A(0,0).GetNumOfElements(); v++) {

				for(size_t p=0; p<k; p++)
					(*psi)(p,i).ElementAtIndex(v)[j] = digits[p];

			}
		}
	}

	return psi;

}

