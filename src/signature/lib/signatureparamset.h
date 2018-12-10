#ifndef SIGNATURE_PARAMS_SET
#define SIGNATURE_PARAMS_SET
namespace lbcrypto{
    enum SignatureSecurityLevel{
        GPV_1_006546_2,
        GPV_1_006546_8,
        GPV_1_003941_2,
        GPV_1_003941_64,
        GPV_1_003941_512
    };
    struct SignatureParamSet{
        unsigned int ringsize;
        unsigned int modulusbitwidth;
        unsigned int base;
    };
    vector<SignatureParamSet> SignatureParamsSets({
        {512,24,2},
        {512,24,8},
        {1024,27,2},
        {1024,27,64},
        {1024,27,512},
    });
}
#endif