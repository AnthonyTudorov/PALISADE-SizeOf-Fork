//
// Created by matt on 12/11/15.
//

#ifndef PALISADE_STUDENT_EDITION_BINARYUNIFORMDISTRIBUTION_H
#define PALISADE_STUDENT_EDITION_BINARYUNIFORMDISTRIBUTION_H

#include "Distribution.h"

namespace lbcrypto {
    template<class G>
    class BinaryUniformDistribution : public Distribution<G> {

    public:

        BinaryUniformDistribution (G& generator) : Distribution<G> (generator) {}
        ~BinaryUniformDistribution ();
        BigBinaryInteger nextInteger ();
        BigBinaryVector nextVector (size_t size);

    };
}


#endif //PALISADE_STUDENT_EDITION_BINARYUNIFORMDISTRIBUTION_H
