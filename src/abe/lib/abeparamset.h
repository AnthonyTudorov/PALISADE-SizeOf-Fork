#ifndef ABE_PARAMS_SET_H
#define ABE_PARAMS_SET_H
namespace lbcrypto{
    enum ABESecurityLevel{
        IBE_1_0047227_2,
        IBE_1_0047227_4,
        IBE_1_005514_512,
        IBE_1_005514_1024,
        CPABE_1_005045_6,
        CPABE_1_005818_6,
        CPABE_1_005045_8,
        CPABE_1_005818_8,
        CPABE_1_005204_16,
        CPABE_1_005987_16,
        CPABE_1_005204_20,
        CPABE_1_005987_20,
        CPABE_1_005204_32,
        CPABE_1_006156_32
        };
    struct ABEParamSet{
        usint ringsize;
        usint modulusbitwidth;
        usint base;
        usint numofattributes;
        double stddev;
    };
    vector<ABEParamSet> ABEParamsSets({
        {1024,32,2,1,4.578},
        {1024,32,4,1,4.578},
        {1024,37,512,1,4.578},
        {1024,37,1024,1,4.578},
        {1024,34,2,6,4.578},
        {1024,40,1024,6,4.578},
        {1024,34,2,8,4.578},
        {1024,40,1024,8,4.578},
        {1024,35,2,16,4.578},
        {1024,41,1024,16,4.578},
        {1024,35,2,20,4.578},
        {1024,41,1024,20,4.578},
        {1024,35,2,32,4.578},
        {1024,42,1024,32,4.578},

    });
}
#endif