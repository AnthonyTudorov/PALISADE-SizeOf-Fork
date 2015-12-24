#ifndef LBCRYPTO_LATTICE_TRAPDOOR_H
#define LBCRYPTO_LATTICE_TRAPDOOR_H

using std::pair;

#include "matrix.h"
#include "ilvector2n.h"
namespace lbcrypto {
    typedef ILMat<ILVector2n> RingMat;

    class TrapdoorPair {
    public:
        RingMat r;
        RingMat e;
    };

    inline pair<RingMat, TrapdoorPair> TrapdoorSample(ILParams params, int stddev) {
        auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
        auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianAllocator(params, EVALUATION, stddev);
        size_t n = params.GetCyclotomicOrder() / 2;
        //  k ~= bitlength of q
        size_t k = params.GetModulus().GetMSB();

        //  TODO: sample from uniform [0,q)
        auto a = zero_alloc();

        RingMat r(gaussian_alloc, k, 1);
        RingMat e(gaussian_alloc, k, 1);

        RingMat g = RingMat(zero_alloc, 1, k).GadgetVector();

        RingMat A(zero_alloc, 1, k+2);
        A(0,0) = 1;
        A(0,1) = *a;
        for (size_t i = 0; i < k; ++i) {
            A(0, i+2) = g(0, i) - (*a*r(i, 0) + e(i, 0));
        }

        return pair<RingMat, TrapdoorPair>(A, TrapdoorPair{r, e});
    }
}
#endif
