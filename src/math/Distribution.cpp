//
// Created by matt on 12/11/15.
//

#include "Distribution.h"

namespace lbcrypto {

    template<class G>
    Distribution<G>::Distribution (G &generator) {
        this->generator = generator;
    }
}
