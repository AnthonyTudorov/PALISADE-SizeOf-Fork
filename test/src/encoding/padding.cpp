#include <gtest/gtest.h>
#include "../../../src/encoding/padding.h"

using namespace std;
using namespace lbcrypto;

TEST(OneZeroPad, test_empty) {
    ByteArray empty("");
    OneZeroPad::Pad(8, &empty);
    //  Force string constructor to copy all 7 NULL bytes
    EXPECT_EQ(ByteArray("\x80\0\0\0\0\0\0\0", 8), empty);

    OneZeroPad::Unpad(&empty);
    EXPECT_EQ("", empty);
}

TEST(OneZeroPad, test_one_char_short) {
    ByteArray partialBlock("almost 22 characters!");
    OneZeroPad::Pad(22, &partialBlock);
    EXPECT_EQ(ByteArray("almost 22 characters!\x80"), partialBlock);

    OneZeroPad::Unpad(&partialBlock);
    EXPECT_EQ(ByteArray("almost 22 characters!"), partialBlock);
}

TEST(OneZeroPad, test_two_chars_short) {
    ByteArray partialBlock("almost 23 characters!");
    OneZeroPad::Pad(23, &partialBlock);
    EXPECT_EQ(ByteArray("almost 23 characters!\x80\0", 23), partialBlock);

    OneZeroPad::Unpad(&partialBlock);
    EXPECT_EQ(ByteArray("almost 23 characters!"), partialBlock);
}

TEST(OneZeroPad, test_full_block) {
    ByteArray fullBlock("21 whole characters!!");
    OneZeroPad::Pad(21, &fullBlock);
    EXPECT_EQ(
        ByteArray(
        "21 whole characters!!\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 42
        ),
        fullBlock
        );
}
