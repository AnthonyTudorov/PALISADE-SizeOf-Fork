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

    inline RingMat GaussSamp(size_t n, size_t k, const RingMat& A, const TrapdoorPair& T, const RingMat& u, double sigma) {
        int32_t c(ceil(2 * sqrt(log(2*n*(1 + 1/4e-22)) / M_PI)));
        const BigBinaryInteger& modulus = A(0,0).GetModulus();
        auto singleElemBinVecAlloc = [=](){ return make_unique<BigBinaryVector>(1, modulus); };

        ILMat<BigBinaryVector> R = Rotate(T.m_e)
            .VStack(Rotate(T.m_r))
            .VStack(ILMat<BigBinaryVector>(singleElemBinVecAlloc, n*k, n*k).Identity());
        //  TODO: use length 1 binvec so we can subtract and have negatives mod q
        //  Convert to int32 later inside nonspherical sample
        BigBinaryVector const& cSquared = BigBinaryVector::Single(
            BigBinaryInteger(c*c), modulus
            );
        ILMat<BigBinaryVector> COV = R*R.Transpose().ScalarMult(cSquared);
        std::cout << COV << std::endl;

        BigBinaryVector const& sigmaSquared = BigBinaryVector::Single(
            BigBinaryInteger(ceil(sigma*sigma)), modulus
            );
        ILMat<BigBinaryVector> SigmaP = ILMat<BigBinaryVector>(singleElemBinVecAlloc, COV.GetRows(), COV.GetCols()).Identity().ScalarMult(sigmaSquared) - COV;

        ILMat<int32_t> p([](){ return make_unique<int32_t>(); }, (2+k)*n, 1);
        NonSphericalSample(n, modulus, SigmaP, c, &p);

        return A;
    }
}
#endif
