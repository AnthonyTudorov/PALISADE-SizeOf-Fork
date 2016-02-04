#ifndef LBCRYPTO_LATTICE_TRAPDOOR_H
#define LBCRYPTO_LATTICE_TRAPDOOR_H

using std::pair;

#include "matrix.h"
#include "../lattice/ilvector2n.h"
#include "dgsampling.h"

namespace lbcrypto {

	typedef ILMat<ILVector2n> RingMat;

    class TrapdoorPair {
    public:
        RingMat m_r;
        RingMat m_e;

		TrapdoorPair(const RingMat &r, const RingMat &e): m_r(r), m_e(e) {};
    };

    inline pair<RingMat, TrapdoorPair> TrapdoorSample(ILParams params, int stddev) {
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
        auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, EVALUATION, stddev);
		auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, EVALUATION);
        size_t n = params.GetCyclotomicOrder() / 2;
        //  k ~= bitlength of q
        size_t k = params.GetModulus().GetMSB();

        auto a = uniform_alloc();

        RingMat r(gaussian_alloc, 1, k);
        RingMat e(gaussian_alloc, 1, k);

        RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

        RingMat A(zero_alloc, 1, k+2);
        A(0,0) = 1;
        A(0,1) = *a;
        for (size_t i = 0; i < k; ++i) {
            A(0, i+2) = g(0, i) - (*a*r(0, i) + e(0, i));
        }

        return pair<RingMat, TrapdoorPair>(A, TrapdoorPair(r, e));
    }

    inline RingMat GaussSamp(size_t n, size_t k, const RingMat& A, const TrapdoorPair& T, const ILMat<LargeFloat> &SigmaP, const ILVector2n &u, 
		double sigma, DiscreteGaussianGenerator &dgg) {

		const ILParams &params = u.GetParams();
		auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);

		//We should convert this to a static variable later
		int32_t c(ceil(2 * sqrt(log(2*n*(1 + 1/4e-22)) / M_PI)));

        const BigBinaryInteger& modulus = A(0,0).GetModulus();

        ILMat<int32_t> p([](){ return make_unique<int32_t>(); }, (2+k)*n, 1);
        NonSphericalSample(n, SigmaP, c, &p);

		//std::cout << "GaussSamp: Just finished running NonSphericalSample" << std::endl;

		// pHat is in the coefficient representation
		ILMat<ILVector2n> pHat = SplitInt32IntoILVector2nElements(p,n,params);
	
		// Now pHat is in the evaluation representation
		pHat.SwitchFormat();

		// YSP It is assumed that A has dimension 1 x (k + 2) and pHat has the dimension of (k + 2) x 1
		// perturbedSyndrome is in the evaluation representation
		ILVector2n perturbedSyndrome = u - (A.Mult(pHat))(0,0);

		ILMat<BigBinaryInteger> zHatBBI(BigBinaryInteger::Allocator, k, n);

		// GaussSampG(perturbedSyndrome,sigma,k,dgg,&zHatBBI);

		// converting perturbed syndrome to coefficient representation
		perturbedSyndrome.SwitchFormat();

		std::cout << "GaussSamp: About to run GaussSampGq" << std::endl;

		GaussSampGq(perturbedSyndrome,sigma,k,modulus,dgg,&zHatBBI);

		std::cout << "GaussSamp: Just ran GaussSampGq" << std::endl;

		// Convert zHat from a matrix of BBI to a vector of ILVector2n ring elements
		// zHat is in the coefficient representation
		RingMat zHat = SplitBBIIntoILVector2nElements(zHatBBI,n,params);
		// Now converting it to the evaluation representation before multiplication
		zHat.SwitchFormat();

		RingMat zHatPrime(zero_alloc, k + 2, 1);

		zHatPrime(0,0) = pHat(0,0) + T.m_e.Mult(zHat)(0,0);
		zHatPrime(1,0) = pHat(1,0) + T.m_r.Mult(zHat)(0,0);

		for (size_t row = 2; row < k + 2; ++row)
			zHatPrime(row,0) = pHat(row,0) + zHat(row-2,0);

        return zHatPrime;

    }

inline void PerturbationMatrixGen(size_t n, size_t k, const RingMat& A, const TrapdoorPair& T, double s, ILMat<LargeFloat> *sigmaSqrt) {

		//We should convert this to a static variable later
		int32_t c(ceil(2 * sqrt(log(2*n*(1 + 1/4e-22)) / M_PI)));

        const BigBinaryInteger& modulus = A(0,0).GetModulus();

		//Computing e and r in coefficient representation
		ILMat<ILVector2n> eCoeff = T.m_e;
		eCoeff.SwitchFormat();
		ILMat<ILVector2n> rCoeff = T.m_r;
		rCoeff.SwitchFormat();

        //ILMat<BigBinaryInteger> R = Rotate(T.m_e)
        //    .VStack(Rotate(T.m_r))
        //    .VStack(ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, n*k, n*k).Identity());

        ILMat<BigBinaryInteger> R = Rotate(eCoeff)
            .VStack(Rotate(rCoeff))
            .VStack(ILMat<BigBinaryInteger>(BigBinaryInteger::Allocator, n*k, n*k).Identity());

        ILMat<int32_t> Rint = ConvertToInt32(R, modulus);
        ILMat<int32_t> COV = Rint*Rint.Transpose().ScalarMult(c*c);

        ILMat<int32_t> SigmaP = ILMat<int32_t>([](){ return make_unique<int32_t>(); }, COV.GetRows(), COV.GetCols()).Identity().ScalarMult(s*s) - COV;

        ILMat<int32_t> p([](){ return make_unique<int32_t>(); }, (2+k)*n, 1);

		int32_t a(floor(c/2));

		// YSP added the a^2*I term which was missing in the original LaTex document
		ILMat<int32_t> sigmaA = SigmaP - (a*a)*ILMat<int32_t>(SigmaP.GetAllocator(), SigmaP.GetRows(), SigmaP.GetCols()).Identity();

		*sigmaSqrt = Cholesky(sigmaA);

    }
}
#endif
