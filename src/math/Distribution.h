//
// Created by matt on 12/11/15.
//

#ifndef DISTRIBUTION_H
#define DISTRIBUTION_H

#include "backend.h"

namespace lbcrypto {
    template<class G>
    class Distribution {
    public:

        Distribution (G& generator);

        virtual ~Distribution () = 0;

        virtual BigBinaryInteger nextInteger () = 0;

        virtual BigBinaryVector nextVector () = 0;

    protected:

        G& generator;
    };
}

#endif // DISTRIBUTION_H
