#include <gtest/gtest.h>
#include "../../../src/encoding/padding.h"

using namespace std;
using namespace lbcrypto;

TEST(OneZeroPad, test_empty) {
    ByteArray empty;
    OneZeroPad::Pad(8, &empty);
    //  Force string constructor to copy all 7 NULL bytes
    EXPECT_EQ(ByteArray({0x80, 0, 0, 0, 0, 0, 0, 0}), empty);

    OneZeroPad::Unpad(&empty);
    EXPECT_EQ(ByteArray(), empty);
}

TEST(OneZeroPad, test_one_char_short) {
    ByteArray partialBlock = ByteArrayFromString("almost 22 characters!");
    OneZeroPad::Pad(22, &partialBlock);
    EXPECT_EQ(ByteArrayFromString("almost 22 characters!\x80"), partialBlock);

    OneZeroPad::Unpad(&partialBlock);
    EXPECT_EQ(ByteArrayFromString("almost 22 characters!"), partialBlock);
}

TEST(OneZeroPad, test_two_chars_short) {
    ByteArray partialBlock = ByteArrayFromString("almost 23 characters!");
    OneZeroPad::Pad(23, &partialBlock);
    EXPECT_EQ(ByteArrayFromString("almost 23 characters!\x80\0", 23), partialBlock);

    OneZeroPad::Unpad(&partialBlock);
    EXPECT_EQ(ByteArrayFromString("almost 23 characters!"), partialBlock);
}

TEST(OneZeroPad, test_full_block) {
    ByteArray fullBlock = ByteArrayFromString("21 whole characters!!");
    OneZeroPad::Pad(21, &fullBlock);
    EXPECT_EQ(
        ByteArrayFromString(
        "21 whole characters!!\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 42
        ),
        fullBlock
        );

    OneZeroPad::Unpad(&fullBlock);
    EXPECT_EQ(ByteArrayFromString("21 whole characters!!"), fullBlock);
}

TEST(ZeroPad, test_one_byte_short) {
    ByteArray oneShort{0,1,2};
    ZeroPad::Pad(4, &oneShort);

    EXPECT_EQ(ByteArray({0,1,2,0}), oneShort);

    ZeroPad::Unpad(&oneShort);
    EXPECT_EQ(
        ByteArray({0,1,2}),
        oneShort
        );

}
