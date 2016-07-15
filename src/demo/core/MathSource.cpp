// This is a main() file built to test math  operations
// D. Cousins

#include <iostream>
#include <fstream>
#include "../../lib/utils/inttypes.h"
#include "../../lib/math/backend.h"
#if 1
#include "../../lib/math/nbtheory.h"
#include "../../lib/math/distrgen.h"
#include "../../lib/lattice/elemparams.h"
#include "../../lib/lattice/ilparams.h"
#include "../../lib/lattice/ildcrtparams.h"
#include "../../lib/lattice/ilelement.h"
#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.h"
#include "../../lib/obfuscate/lweconjunctionobfuscate.cpp"
#include "../../lib/obfuscate/obfuscatelp.h"
#endif
#include "time.h"
#include <chrono>

#include "../../lib/utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;


//define the main sections of the test
void test_BigBinaryInt(void); 	// test old version of big int
void test_BigBinaryVector(void); // test old version of big int vector
void test_ubint(void);		 // test new version of ubint
void test_ubintvec(void);	 // test new vector version

int divmain(void);

//main()   need this for Kurts' makefile to ignore this.
int main(int argc, char* argv[]){

  //  divmain();
  //  return 0;
  //  //test_BigBinaryInt();
  test_BigBinaryVector();
  //test_ubint();
  test_ubintvec();

  return 0;
}


void test_BigBinaryInt () {
  cout<<"testing BigBinaryInt"<<endl;
  //Todo: add some timing tests

  return;
}

//helper function that bulds BigBinaryVector from a vector of strings
BigBinaryVector BBVfromStrvec( std::vector<std::string> &s) {
  BigBinaryVector a(s.size());
  for (usint i = 0; i< s.size(); i++){
    a.SetValAtIndex(i,s[i]);
  }
  return a;
}

//main BigBinaryVector test suite. tests math
void test_BigBinaryVector () {
  int nloop = 1000; //number of times to run each test for timing.

  bool dbg_flag = 1;		// if true then print dbg output


  TimeVar t1,t2,t3,t_total; // timers for TIC() TOC()
  double time1;		    // captures the time in usec.
  double time2;
  double time3;
  double timeTotal;		// overal time


  //there are two test cases, 1) small modulus 2)approx 48 bits.

  //note this fails BigBinaryInteger q1 = {"00000000000000163841"};
  BigBinaryInteger q1 ("00000000000000163841");
  BigBinaryInteger q2 ("00004057816419532801");

  // for each vector, define a, b inputs as vectors of strings
  std::vector<std::string> a1strvec = {
    "00000000000000127753", "00000000000000077706",
    "00000000000000017133", "00000000000000022582",
    "00000000000000112132", "00000000000000027625",
    "00000000000000126773", "00000000000000008924",
    "00000000000000125972", "00000000000000002551",
    "00000000000000113837", "00000000000000112045",
    "00000000000000100953", "00000000000000077352",
    "00000000000000132013", "00000000000000057029", };

  // this fails too!!! BigBinaryVector a1(a1string);
  // so I wrote this function
  BigBinaryVector a1 = BBVfromStrvec(a1strvec);
  a1.SetModulus(q1);

  std::vector<std::string> a2strvec = {
    "00000185225172798255", "00000098879665709163",
    "00003497410031351258", "00004012431933509255",
    "00001543020758028581", "00000135094568432141",
    "00003976954337141739", "00004030348521557120",
    "00000175940803531155", "00000435236277692967",
    "00003304652649070144", "00002032520019613814",
    "00000375749152798379", "00003933203511673255",
    "00002293434116159938", "00001201413067178193", };

  BigBinaryVector a2 = BBVfromStrvec(a2strvec);
  a2.SetModulus(q2);

  //b:
  std::vector<std::string> b1strvec = 
    { "00000000000000066773", "00000000000000069572",
      "00000000000000142134", "00000000000000141115",
      "00000000000000123182", "00000000000000155822",
      "00000000000000128147", "00000000000000094818",
      "00000000000000135782", "00000000000000030844",
      "00000000000000088634", "00000000000000099407",
      "00000000000000053647", "00000000000000111689",
      "00000000000000028502", "00000000000000026401", };
  
  BigBinaryVector b1  = BBVfromStrvec(b1strvec);
  b1.SetModulus(q1);
  
  std::vector<std::string> b2strvec = 
    { "00000698898215124963", "00000039832572186149",
      "00001835473200214782", "00001041547470449968",
      "00001076152419903743", "00000433588874877196",
      "00002336100673132075", "00002990190360138614",
      "00000754647536064726", "00000702097990733190",
      "00002102063768035483", "00000119786389165930",
      "00003976652902630043", "00003238750424196678",
      "00002978742255253796", "00002124827461185795", };

  BigBinaryVector b2 = BBVfromStrvec(b2strvec);
  b2.SetModulus(q2);

  //now test all mod functions Note BigBinaryVector implies modulus ALWAYS

  //load correct values of math functions of a and b
  //modadd:
  std::vector<std::string>  modsum1strvec =
    {"00000000000000030685", "00000000000000147278",
     "00000000000000159267", "00000000000000163697",
     "00000000000000071473", "00000000000000019606",
     "00000000000000091079", "00000000000000103742",
     "00000000000000097913", "00000000000000033395",
     "00000000000000038630", "00000000000000047611",
     "00000000000000154600", "00000000000000025200",
     "00000000000000160515", "00000000000000083430", };
  BigBinaryVector modsum1 = BBVfromStrvec(modsum1strvec);
  modsum1.SetModulus(q1);
  
  std::vector<std::string> modsum2strvec =
    {"00000884123387923218", "00000138712237895312",
     "00001275066812033239", "00000996162984426422",
     "00002619173177932324", "00000568683443309337",
     "00002255238590741013", "00002962722462162933",
     "00000930588339595881", "00001137334268426157",
     "00001348899997572826", "00002152306408779744",
     "00000294585635895621", "00003114137516337132",
     "00001214359951880933", "00003326240528363988", };
  BigBinaryVector modsum2 = BBVfromStrvec(modsum2strvec);
  modsum2.SetModulus(q2);
  
  // modsub:
  std::vector<std::string>  moddiff1strvec =
    {   "00000000000000060980", "00000000000000008134",
	"00000000000000038840", "00000000000000045308",
	"00000000000000152791", "00000000000000035644",
	"00000000000000162467", "00000000000000077947",
	"00000000000000154031", "00000000000000135548",
	"00000000000000025203", "00000000000000012638",
	"00000000000000047306", "00000000000000129504",
	"00000000000000103511", "00000000000000030628", };
  BigBinaryVector moddiff1 = BBVfromStrvec(moddiff1strvec);
  moddiff1.SetModulus(q1);
  
  std::vector<std::string>  moddiff2strvec =
    {   "00003544143377206093", "00000059047093523014",
	"00001661936831136476", "00002970884463059287",
	"00000466868338124838", "00003759322113087746",
	"00001640853664009664", "00001040158161418506",
	"00003479109686999230", "00003790954706492578",
	"00001202588881034661", "00001912733630447884",
	"00000456912669701137", "00000694453087476577",
	"00003372508280438943", "00003134402025525199", };
  BigBinaryVector moddiff2 = BBVfromStrvec(moddiff2strvec);
  moddiff2.SetModulus(q2);
  
  //modmul:
  
  std::vector<std::string> modmul1strvec =
    { "00000000000000069404", "00000000000000064196",
      "00000000000000013039", "00000000000000115321",
      "00000000000000028519", "00000000000000151998",
      "00000000000000089117", "00000000000000080908",
      "00000000000000057386", "00000000000000039364",
      "00000000000000008355", "00000000000000146135",
      "00000000000000061336", "00000000000000031598",
      "00000000000000025961", "00000000000000087680", };
  
  
  BigBinaryVector modmul1 = BBVfromStrvec(modmul1strvec);
  modmul1.SetModulus(q2);

  std::vector<std::string> modmul2strvec =
    { "00000585473140075497", "00003637571624495703",
      "00001216097920193708", "00001363577444007558",
      "00000694070384788800", "00002378590980295187",
      "00000903406520872185", "00000559510929662332",
      "00000322863634303789", "00001685429502680940",
      "00001715852907773825", "00002521152917532260",
      "00000781959737898673", "00002334258943108700",
      "00002573793300043944", "00001273980645866111", };

  BigBinaryVector modmul2 = BBVfromStrvec(modmul2strvec);
  modmul2.SetModulus(q2);

  BigBinaryVector c1,c2;	// result vectors

  // compute results for each function and compare.

  TIC(t_total);
  bool good = true;

  // test mod add for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModAdd(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModAdd(b1) computation time: " << "\t" << time1 << " us");
  if (c1 != modsum1)
    cout << "bad add! "<<endl;

  // test mod sub for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModSub(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModSub(b1) computation time: " << "\t" << time1 << " us");
  if(c1 !=moddiff1)
    cout << "bad sub! "<<endl;

  //test mod modmultiply for both cases
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModMul(b1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModMul(b1) computation time: " << "\t" << time1 << " us");
  if (c1 != modmul1)
    cout << "bad multiply! "<<endl;


  // test case two
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModAdd(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModAdd(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != modsum2)
    cout << "bad modadd! "<<endl;

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModSub(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModSub(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != moddiff2)
    cout << "bad modsub! "<<endl;

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModMul(b2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModMul(b2) computation time: " << "\t" << time2 << " us");
  if (c2 != modmul2)
    cout << "bad modmultiply! "<<endl;

  timeTotal = TOC(t_total);
  DEBUG("Total time: " << "\t" << timeTotal << " us");

  return;
}

void iftest (bool t, string v) {
  if (t) {
    cout <<"Fail ";
    cout<<v<<endl;
    //exit(-1);
  }else {
    cout <<"Succeed ";
    cout<<v<<endl;
  }

  return;
}

/////////////////////////////////////////////////////////////
void test_ubint () {
  bool dbg_flag = 1;
  cout<<"testing bint"<<endl;


  { //crate a small ubint
    cout<<"todo test divided by and /  and math for very big ints"<<endl;

    ubint q1("00000000000000163841");
    //cout << "q1 contents"<<endl;
    //q1.PrintLimbsInDec();
    //create a large bing
    ubint q2("00004057816419532801");
    //cout << "q2 contents"<<endl;
    //q2.PrintLimbsInDec();
    usint msb = q2.GetMSB();
    //DEBUG("q2 msb "<<msb);
    iftest (msb != 52 ,"msb test ");
  }

  //TEST(method_to_test_convert_to_double, ConvertToDouble)
  {
    ubint x("104037585658683683");
    double xInDouble = 104037585658683683;

    //DEBUG("x.tostring "<< x.ToString());
    //DEBUG("xInDouble "<< xInDouble);
    //DEBUG("x.ConvertToDouble "<< x.ConvertToDouble());
    iftest (xInDouble != x.ConvertToDouble()	," testing convert to double");
  }

  /****************************/
  /* TESTING SHIFT OPERATORS  */
  /****************************/

  /*******************************************************/
  /* TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS */
  /*******************************************************/

  // The operator 'Left Shift' operates on BigBinary Integer a, and it
  // is shifted by a number

  // Returns: a<<(num), and the result is stored in BigBinaryInterger
  // calculatedResult 'a' is left shifted by 'num' number of bits, and
  // filled up by 0s from right which is equivalent to a * (2^num)
  //
  //        example:
  //            4<<3 => (100)<<3 => (100000) => 32
  //           this is equivalent to: 4* (2^3) => 4*8 =32

  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  //todo change for new limb.
  {
    ubint a("39960");
    usshort shift = 3;

    ubint calculatedResult = a<<(shift);
    int expectedResult = 319680;

    iftest (expectedResult != calculatedResult.ConvertToUsint()
	    ,"testing << less than max shift");
  }

  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39960");
    usshort shift = 6;

    ubint calculatedResult = a<<(shift);
    int expectedResult = 2557440;

    iftest (expectedResult != calculatedResult.ConvertToUsint(),"testing <<  greater_than max shift");
  }
  // TEST CASE WHEN SHIFT IS multi limb
  {
    ubint a("138712237895312");
    usshort shift = 8;

    usint msb = a.GetMSB();
    //DEBUG("a.msb " <<msb);

    ubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 35510332901199872;
    //DEBUG("expectedResult 35510332901199872 ="<<expectedResult);

    iftest (expectedResult != calculatedResult.ConvertToUint64(),"testing << multi limb");
  }

  {

    ubint a("1024");
    usshort shift = 48;

    ubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 288230376151711744;
    uint64_t result =calculatedResult.ConvertToUint64();
    //
    //    cout<<"results "<<endl;
    //    cout<<std::hex<< expectedResult<<endl;
    //    cout<<std::hex<< result<<endl;
    //    cout<<std::dec<<endl;
    //
    iftest (expectedResult != calculatedResult.ConvertToUint64(), "testing << greater than limb size");

  }

  /************************************************/
  /* TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS -*/
  /************************************************/

  // The operator 'Left Shift Equals' operates on BigBinary Integer a,
  // and it is shifted by a number
  // Returns:
  // a<<(num), and the result is stored in 'a'
  // 'a' is left shifted by 'num' number of bits, and filled up by 0s
  // from right which is equivalent to a * (2^num)
  // example :4<<3 => (100)<<3 => (100000) => 32
  // this is equivalent to: 4* (2^3) => 4*8 =32
  //
  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39960");
    usshort num = 3;

    a<<=(num);
    int expectedResult = 319680;

    iftest (expectedResult != a.ConvertToUsint()
	    ,"testing <<= shift equals less than max shift");
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39960");
    usshort num = 6;

    a<<=(num);
    usint expectedResult = 2557440;

    iftest (expectedResult != a.ConvertToUsint(), "testing <<=left shift equals greater than max shift");
  }
  {

    ubint a("1024");
    usshort shift = 48;

    a<<=(shift);
    usint expectedResult = 288230376151711744;
    usint Result = a.ConvertToUsint();
    iftest (expectedResult != Result, "testing <<= greater than limb size");
  }

  /********************************************************/
  /* TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS */
  /********************************************************/
  // The operator 'Right Shift' operates on BigBinary Integer a, and it
  // is shifted by a number

  // Returns: a>>(num), and the result is stored in BigBinary Integer
  // calculated. Result 'a' is right shifted by 'num' number of bits,
  // and filled up by 0s from left which is equivalent to a / (2^num)

  //  ex:4>>3 => (100000)>>3 => (000100) => 4

  // this is equivalent to: 32*(2^3) => 32/8 = 4


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39965675");
    usshort shift = 3;

    ubint calculatedResult = a>>(shift);
    usint expectedResult = 4995709;

    iftest (expectedResult != calculatedResult.ConvertToUsint()
	    ,"testing >> less than max shift");
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39965675");
    usshort shift = 6;

    ubint calculatedResult = a>>(shift);
    usint expectedResult = 624463;

    iftest (expectedResult != calculatedResult.ConvertToUsint()
	    ,"testing >> greater than max shift");
  }


  /***************************************************************/
  /* TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS */
  /***************************************************************/

  // The operator 'Right Shift Equals' operates on BigBinary Integer a,
  // and it is shifted by a number

  // Returns: a>>=(num), and the result is stored in a 'a' is right
  // shifted by 'num' number of bits, and filled up by 0s from left
  // which is equivalent to a / (2^num)

  //   ex:4>>3 => (100000)>>3 => (000100) => 4

  //   this is equivalent to: 32*(2^3) => 32/8 = 4
  //   ConvertToUsint converts ubint calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39965675");
    usshort shift = 3;

    a>>=(shift);
    usint expectedResult = 4995709;

    iftest (expectedResult != a.ConvertToUsint(), "testing >>= less than max shift");
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    ubint a("39965675");
    usshort shift = 6;

    a>>=(shift);
    usint expectedResult = 624463;

    iftest (expectedResult != a.ConvertToUsint(), "testing >>= greater than max shift");
  }
  {

    ubint a(" 288230376151711744");
    usshort shift = 48;

    a>>=(shift);
    usint expectedResult = 1024;

    iftest (expectedResult != a.ConvertToUsint(), "testing >>= greater than limb size");
  }
  /************************************************/
  /* TESTING BASIC COMPARATOR METHODS AND OPERATORS */
  /**************************************************/

  /************************************************/
  /* TESTING METHOD COMPARE and gt, lt, eq, neq FOR ALL CONDITIONS    */
  /************************************************/

  // The method "Comapare" comapres two BigBinary Integers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as  if  takes integer
  {
    sint c;
    sint expectedResult;
    bool cbool;

    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
    {
      ubint a("2124827461185795");
      ubint b("1201413067178193");

      c = a.Compare(b);
      expectedResult = 1;
      iftest (expectedResult !=c,"testing compare a greater than b");
      cbool= a>b;
      iftest (cbool != true,"testing > a > b");
      cbool= a<b;
      iftest (cbool != false,"testing < a > b");
      cbool= a==b;
      iftest (cbool != false,"testing == a > b");
      cbool= a!=b;
      iftest (cbool != true,"testing != a > b");

    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
    {
      ubint a("1201413067178193");
      ubint b("2124827461185795");


      c = a.Compare(b);
      expectedResult = -1;

      iftest (expectedResult !=(int)c	,"testing compare a less than b");
      cbool= a>b;
      iftest (cbool != false,"testing > a > b");
      cbool= a<b;
      iftest (cbool != true,"testing < a > b");
      cbool= a==b;
      iftest (cbool != false,"testing == a > b");
      cbool= a!=b;
      iftest (cbool != true,"testing != a > b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
    {
      ubint a("2124827461185795");
      ubint b("2124827461185795");

      c = a.Compare(b);
      expectedResult = 0;

      iftest (expectedResult !=(int)c	,"testing compare a equals b");
      cbool= a>b;
      iftest (cbool != false,"testing > a > b");
      cbool= a<b;
      iftest (cbool != false,"testing < a > b");
      cbool= a==b;
      iftest (cbool != true,"testing == a > b");
      cbool= a!=b;
      iftest (cbool != false,"testing != a > b");
    }

  }
  /****************************/
  /* TESTING MATH OPERATORS  */
  /****************************/


  DEBUG("math operations");
  {
    ubint calculatedResult;
    uint64_t expectedResult;
    string expectedResultStr; //for when ubint is > 64 bits.
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      ubint a("203450");
      ubint b("2034");

      calculatedResult = a.Add(b);
      expectedResult = 205484;

      uint64_t result = calculatedResult.ConvertToUint64();

      //DEBUG("result "<<result);
      //DEBUG("expect "<<expectedResult);
      iftest (expectedResult!= result,"testing + a greater than b");
    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      ubint a("2034");
      ubint b("203450");


      calculatedResult = a.Add(b);
      expectedResult = 205484;

      iftest (expectedResult != calculatedResult.ConvertToUint64()
	      ,"testing + a less than b");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // LIMB
    //todo: redo this to test overflow to next limb!!
    {
      ubint a("4294967295");
      ubint b("1");

      calculatedResult = a.Add(b);
      expectedResult = 4294967296;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),
	      "testing + overflow to next limb");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    //todo change for limb
    {
      ubint a("35");
      ubint b("1015");

      calculatedResult = a.Add(b);
      expectedResult = 1050;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),
	      "testing + no overflow to next byte");
    }
    // TEST CASE WHEN both are multi limb numbers
    {
      ubint a("98879665709163");
      ubint b("39832572186149");

      calculatedResult = a.Add(b);
      expectedResult = 138712237895312;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),
	      "testing + multi limb");
    }

    /************************************************/
    /* TESTING OPERATOR += FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "+=(Plus Equals)" does addition of two BigBinary
    // Integers a,b Calculates a+b, and stores result in a ConvertToUsint
    // converts BigBinaryInteger8y a to integer


    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      ubint a("2034");
      ubint b("203");

      a+=b;
      expectedResult = 2237;

      iftest (expectedResult != a.ConvertToUint64(),"testing += a greater than b");
    }
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
    // HAS NO OVERFLOW
    {
      ubint a("2034");
      ubint b("203450");

      a+=b;
      expectedResult = 205484;

      iftest (expectedResult != a.ConvertToUint64(), "testing += a less than b");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
    // BYTE
    {
      //todo change for limb
      ubint a("768900");
      ubint b("16523408");

      a+=b;
      expectedResult = 17292308;

      iftest (expectedResult !=a.ConvertToUint64(),"testing += overflow to next byte");
    }
    // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
    // BYTE
    //change for limb
    {
      ubint a("35");
      ubint b("1015");

      a+=b;
      expectedResult = 1050;

      iftest (expectedResult !=a.ConvertToUint64(),"testing += no overflow to next byte");
    }
    /************************************************/
    /* TESTING METHOD MINUS FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Minus" does subtraction on two BigBinary Integers a,b
    // Returns a-b, which is stored in another BigBinary Integer
    // calculatedResult When a<b, the result is 0, since there is no
    // support for negative numbers as of now ConvertToUint64 converts
    // uubint calculatedResult to integer

    {
      // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

      ubint a("20489");
      ubint b("2034455");

      calculatedResult = a.Sub(b);
      expectedResult = 0;

      //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
      //ZERO
      iftest (expectedResult != calculatedResult.ConvertToUint64(), "testing minus a less than b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
      ubint a("2048956567");
      ubint b("2048956567");

      calculatedResult = a.Sub(b);
      expectedResult = 0;

      iftest (expectedResult != calculatedResult.ConvertToUint64(),"testing minus a equal to b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
      ubint a("2048956567");
      ubint b("2034455");

      calculatedResult = a.Sub(b);
      expectedResult = 2046922112;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(), "testing minus a greater than b");
    }
    // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
      //todo: change for limb
      ubint a("196737");
      ubint b("65406");

      calculatedResult = a.Sub(b);
      expectedResult = 131331;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing minus borrow from next byte");
    }
    // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
      // change for limb
      ubint a("98879665709163");
      ubint b("39832572186149");

      calculatedResult = a.Sub(b);
      expectedResult = 59047093523014;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing minus multi limb");
    }
    /************************************************/
    /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
    /************************************************/

    // The operator "-=(Minus Equals)" does subtractionn of two BigBinary
    // Integers a,b Calculates a-b, and stores result in a Results to 0,
    // when a<b, since there is no concept of negative number as of now
    // ConvertToUint64 converts ubint a to integer
    {
      // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

      ubint a("20489");
      ubint b("2034455");

      a-=b;
      expectedResult = 0;

      //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
      //ZERO
      iftest (expectedResult != a.ConvertToUint64(), "testing -= a less than b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {
      ubint a("2048956567");
      ubint b("2048956567");

      a-=b;
      expectedResult = 0;

      iftest (expectedResult != a.ConvertToUint64(), "testing -= a equal to b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {

      ubint a("2048956567");
      ubint b("2034455");

      a-=b;
      expectedResult = 2046922112;

      iftest (expectedResult !=a.ConvertToUint64(), "testing -= a greater than b");
    }
    // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
    {
      //change for limb
      ubint a("196737");
      ubint b("65406");

      a-=b;
      expectedResult = 131331;

      iftest (expectedResult !=a.ConvertToUint64(), "testing -= borrow from next byte");
    }

    /************************************************/
    /* TESTING METHOD TIMES FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Times" does multiplication on two BigBinary Integers
    // a,b Returns a*b, which is stored in another BigBinary Integer
    // calculatedResult ConvertToUint64 converts ubint
    // calculatedResult to integer
    {
      //ask about the branching if (b.m_MSB==0 or 1)
      ubint a("1967");
      ubint b("654");

      calculatedResult = a.Mul(b);
      expectedResult = 1286418;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing times single limb");
    }
    /************************************************/
    /* TESTING METHOD TIMES FOR ALL CONDITIONS      */
    /************************************************/

    // The method "Times" does multiplication on two BigBinary Integers
    // a,b Returns a*b, which is stored in another BigBinary Integer
    // calculatedResult ConvertToUint64 converts ubint
    // calculatedResult to integer
    {
      //ask about the branching if (b.m_MSB==0 or 1)
      ubint a("98879665709163");
      ubint b("39832572186149");

      calculatedResult = a.Mul(b);
      expectedResultStr = "3938631422102517149330983287";
      iftest (expectedResultStr !=calculatedResult.ToString(),"testing times multi limb");
    }
    /************************************************/
    /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
    /************************************************/

    // The method "Divided By" does division of BigBinary Integer a by
    // another BigBinary Integer b Returns a/b, which is stored in another
    // BigBinary Integer calculatedResult ConvertToUint64 converts
    // ubint calculatedResult to integer When b=0, throws
    // error, since division by Zero is not allowed When a<b, returns 0,
    // since decimal value is not returned


    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
    {
      ubint a("2048");
      ubint b("2034455");

      calculatedResult = a.DividedBy(b);
      expectedResult = 0;

      //RESULT SHOULD BE ZERO
      iftest (expectedResult != calculatedResult.ConvertToUint64(),"testing divided by a less than b");
    }
    // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
    {

      ubint a("2048956567");
      ubint b("2048956567");

      calculatedResult = a.DividedBy(b);
      expectedResult = 1;

      iftest (expectedResult != calculatedResult.ConvertToUint64(),"testing divided by a equals b");
    }
    // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
    {
      ubint a("2048956567");
      ubint b("2034455");

      calculatedResult = a.DividedBy(b);
      expectedResult = 1007;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing divided by a greater than b");
    }

    // TEST CASE for MULTI LIMB

    {
      ubint a("3938631422102517149330983287");
      ubint b("98879665709163");


      calculatedResult = a.DividedBy(b);
      expectedResult = 39832572186149;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing divided by multi limb");
    }
  }
  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigBinary Integers
  // m,p Returns (m mod p), which is stored in another BigBinary Integer
  // calculatedResult ConvertToUint64 converts ubint r to
  // integer
  {
    ubint calculatedResult;
    int expectedResult;
    // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
    {
      ubint m("27");
      ubint p("240");

      calculatedResult = m.Mod(p);
      expectedResult = 27;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod number less than modulus");
    }
    // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
    {
      ubint m("93409673");
      ubint p("406");

      calculatedResult = m.Mod(p);
      expectedResult = 35;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod number greater than modulus");
    }
    // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
    {
      ubint m("32768");
      ubint p("16");

      calculatedResult = m.Mod(p);
      expectedResult = 0;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod number dividible by modulus");
    }

    // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
    {
      ubint m("67108913");
      ubint p("67108913");

      calculatedResult = m.Mod(p);
      expectedResult = 0;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod number equal to modulus");
    }


    /************************************************/
    /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
    /************************************************/


    /* 	The method "Divided By" does division of BigBinary Integer m by another BigBinary Integer p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigBinary Integer calculatedResult
	ConvertToUint64 converts ubint calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
    */



    // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

    /*TEST(UTBinInt_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

      ubint a("9587");
      ubint b("3591");
      ubint c("177");

      ubint calculatedResult = a.ModBarrett(b,c);
      int expectedResult = 205484;

      std::coutcout <<"\n"<<d.ConvertToUint64()<<"\n";	//for testing purpose

      // if (27,calculatedResult.ConvertToUint64());
      }
    */

    /*************************************************/
    /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
    /*************************************************/
    // The method "Mod Inverse" operates on BigBinary Integers m,p
    // Returns {(m)^(-1)}mod p
    //    which is multiplicative inverse of m with respect to p, and is
    //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
    //    of m and p is 1)
    // If m and p are not co-prime, the method throws an error
    // ConvertToUint64 converts ubint calculatedResult to integer


    // TEST CASE WHEN THE NUMBER IS LESS  THAN MOD
    {
      ubint m("5");
      ubint p("108");

      try {
        calculatedResult = m.ModInverse(p);
      } catch (exception& e) {
        cout <<"exception occurred "<< e.what() << endl;

      }

      expectedResult = 65;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod inverse number less than modulus");
    }
    // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
    {
      ubint m("3017");
      ubint p("108");

      try {
        //    		calculatedResult = m.ModInverse(p);
        cout<< "this fails all the time"<<endl;
      } catch (exception& e) {
        cout <<"exception occurred "<< e.what() << endl;

      }

      expectedResult = 77;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing mod inverse non coprimes");
    }


    /************************************************/
    /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
    /************************************************/
    // The method "Mod Add" operates on BigBinary Integers m,n,q
    //   Returns:
    //     (m+n)mod q
    //      = {(m mod q) + (n mod q)}mod q
    //   ConvertToUint64 converts ubint calculatedResult to integer




    // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
      ubint m("58059595");
      ubint n("3768");
      ubint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 2871;

      iftest (expectedResult !=calculatedResult.ConvertToUint64()	,"testing modadd first number greater than modulus");
    }
    // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
    {
      ubint m("595");
      ubint n("376988");
      ubint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 3419;

      iftest (expectedResult !=calculatedResult.ConvertToUint64(),"testing smodadd econd number greater than modulus");
    }
    // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
    {
      ubint m("595");
      ubint n("376");
      ubint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 971;
      iftest (expectedResult != calculatedResult.ConvertToUint64()	,"testing modadd both numbers less than modulus");
    }
    // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
    {

      ubint m("59509095449");
      ubint n("37654969960");
      ubint q("4067");

      calculatedResult = m.ModAdd(n,q);
      expectedResult = 2861;

      iftest (expectedResult != calculatedResult.ConvertToUint64()	,"testing mod add both numbers greater than modulus");
    }

    /************************************************/
    /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
    /************************************************/

    // The method "Mod Sub" operates on BigBinary Integers m,n,q
    //   Returns:
    //    (m-n)mod q
    //    = {(m mod q) - (n mod q)}mod q	when m>n
    //    = 0 when m=n
    //    = {(m mod q)+q-(n mod q)}mod q when m<n

    //   ConvertToUint64 converts ubint calculatedResult to
    //   integer

    //MEMORY ALLOCATION ERROR IN MODSUB METHOD (due to copying value to null pointer)


    // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
    {
      ubint m("595");
      ubint n("399");
      ubint q("406");

      //std::cout << "Before : " << std::endl;

      calculatedResult = m.ModSub(n,q);
      expectedResult = 196;

      iftest (expectedResult != calculatedResult.ConvertToUint64()	,"testing modsub first number greater than modulus");
    }
    // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
    {
      ubint m("39960");
      ubint n("595090959");
      ubint q("406756");

      calculatedResult = m.ModSub(n,q);
      expectedResult = 33029;

      //[{(a mod c)+ c} - (b mod c)] since a < b
      iftest (expectedResult !=calculatedResult.ConvertToUint64()
	      ,"testing modsub first number less than modulus");
    }
    // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
    {
      ubint m("595090959");
      ubint n("595090959");
      ubint q("406756");

      calculatedResult = m.ModSub(n,q);
      expectedResult = 0;

      iftest (expectedResult != calculatedResult.ConvertToUint64()
	      ,"testing modsub first number equals second number");
    }

    /************************************************/
    /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Mul" operates on BigBinary Integers m,n,q
    //   Returns:  (m*n)mod q
    //              = {(m mod q)*(n mod q)}
    // ConvertToUint64 converts ubint calculatedResult to integer

    {
      ubint m("39960");
      ubint n("7959");
      ubint q("406756");

      ubint calculatedResult = m.ModMul(n,q);
      expectedResult = 365204;

      iftest (expectedResult != calculatedResult.ConvertToUint64()
	      ,"testing mod mul test");
    }

    /************************************************/
    /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
    /************************************************/

    // The method "Mod Exp" operates on BigBinary Integers m,n,q
    // Returns:  (m^n)mod q
    //   = {(m mod q)^(n mod q)}mod q
    // ConvertToUint64 converts ubint calculatedResult to integer

    {
      ubint m("39960");
      ubint n("10");
      ubint q("406756");

      ubint calculatedResult = m.ModExp(n,q);
      expectedResult = 139668;

      iftest (expectedResult != calculatedResult.ConvertToUint64()
	      ,"testing mod exp test");
    }
    /****************************************/
    /* TESTING METHOD  BinaryToBigBinaryInt */
    /****************************************/

    {
    std:string binaryString = "1011101101110001111010111011000000011";
      ubint b =
	lbcrypto::ubint::BinaryStringToUbint(binaryString);

      ubint expectedResult("100633769475");
      iftest (expectedResult != b	,"testing BinaryToBigBinaryInt");
    }

    /****************************************/
    /* TESTING METHOD  EXP                  */
    /****************************************/
    {
      ubint x("56");
      ubint result = x.Exp(10);

      ubint expectedResult("303305489096114176");
      iftest (expectedResult != result 	,"testing exp");
    }


  }


  return;
}

//function to compare two bintvecs and print differing indicies
void vec_diff(ubintvec &a, ubintvec &b) {
    for (usint i= 0; i < a.GetLength(); ++i){  //todo change to size()
      if (a.GetValAtIndex(i) != b.GetValAtIndex(i)) {  //todo: add [] indexing to class
        cout << "i: "<< i << endl;
	cout << "first vector " <<endl;
        cout << a.GetValAtIndex(i);
        cout << endl;
        cout << "state " << a.GetValAtIndex(i).m_state << endl;;
        cout << "msb: " << a.GetValAtIndex(i).m_MSB << endl;;
	cout << "second vector " <<endl;
        cout << b.GetValAtIndex(i);
        cout << endl;
        cout << "state " << b.GetValAtIndex(i).m_state << endl;;
        cout << "msb: " << b.GetValAtIndex(i).m_MSB << endl;;
        cout << endl;
      }
    }

}
void vec_diff(mubintvec &a, ubintvec &b) {
    for (usint i= 0; i < a.ubintvec::GetLength(); ++i){  //todo change to size()
      if (a.ubintvec::GetValAtIndex(i) != b.GetValAtIndex(i)) {  //todo: add [] indexing to class
        cout << "i: "<< i << endl;
	cout << "first vector " <<endl;
        cout << a.ubintvec::GetValAtIndex(i);
        cout << endl;
        cout << "state " << a.ubintvec::GetValAtIndex(i).m_state << endl;;
        cout << "msb: " << a.ubintvec::GetValAtIndex(i).m_MSB << endl;;
	cout << "second vector " <<endl;
        cout << b.GetValAtIndex(i);
        cout << endl;
        cout << "state " << b.GetValAtIndex(i).m_state << endl;;
        cout << "msb: " << b.GetValAtIndex(i).m_MSB << endl;;
        cout << endl;
      }
    }


}

void test_ubintvec() {

  int nloop = 1000; //number of times to run each test for timing.

  bool dbg_flag = 1;		// if true then print dbg output

  TimeVar t1,t2,t3,t_total; // timers for TIC() TOC()
  double time1;		    // captures the time in usec.
  double time2;
  double time3;
  double timeTotal;		// overal time

  cout<<"testing ubintvec"<<endl;
cout<<"todo test assignment, < >operators etc. not just math "<<endl;
  //there are two test cases, 1) small modulus 2)approx 48 bits.
  // q1 modulus 1:
  ubint q1("00000000000000163841");
  //cout << "q1 contents"<<endl;
  //q1.PrintLimbsInDec();
  // a1:
  std::vector<std::string>  a1sv =

    { "00000000000000127753", "00000000000000077706",
      "00000000000000017133", "00000000000000022582",
      "00000000000000112132", "00000000000000027625",
      "00000000000000126773", "00000000000000008924",
      "00000000000000125972", "00000000000000002551",
      "00000000000000113837", "00000000000000112045",
      "00000000000000100953", "00000000000000077352",
      "00000000000000132013", "00000000000000057029", };

  ubintvec a1(a1sv);
  mubintvec ma1(a1sv,q1);

  // b1:
  std::vector<std::string>  b1sv = 
    {"00000000000000066773", "00000000000000069572",
     "00000000000000142134", "00000000000000141115",
     "00000000000000123182", "00000000000000155822",
     "00000000000000128147", "00000000000000094818",
     "00000000000000135782", "00000000000000030844",
     "00000000000000088634", "00000000000000099407",
     "00000000000000053647", "00000000000000111689",
     "00000000000000028502", "00000000000000026401", };

  ubintvec b1(b1sv);
  mubintvec mb1(b1sv,q1);

  // add1:
  std::vector<std::string>  add1sv = 
    {"00000000000000194526", "00000000000000147278",
     "00000000000000159267", "00000000000000163697",
     "00000000000000235314", "00000000000000183447",
     "00000000000000254920", "00000000000000103742",
     "00000000000000261754", "00000000000000033395",
     "00000000000000202471", "00000000000000211452",
     "00000000000000154600", "00000000000000189041",
     "00000000000000160515", "00000000000000083430", };

  ubintvec add1(add1sv);

  // sub1:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub1sv = 
    {"00000000000000060980", "00000000000000008134",
     "18446744073709426615", "18446744073709433083",
     "18446744073709540566", "18446744073709423419",
     "18446744073709550242", "18446744073709465722",
     "18446744073709541806", "18446744073709523323",
     "00000000000000025203", "00000000000000012638",
     "00000000000000047306", "18446744073709517279",
     "00000000000000103511", "00000000000000030628", };

#else
  std::vector<std::string> sub1sv = 

    {"00000000000000060980", "00000000000000008134",
     "00000000000000000000", "00000000000000000000",
     "00000000000000000000", "00000000000000000000",
     "00000000000000000000", "00000000000000000000",
     "00000000000000000000", "00000000000000000000",
     "00000000000000025203", "00000000000000012638",
     "00000000000000047306", "00000000000000000000",
     "00000000000000103511", "00000000000000030628", };
#endif
  ubintvec sub1(sub1sv);

  // mul1:
  std::vector<std::string>  mul1sv = 
    {"000000000000000000000000000008530451069",
     "000000000000000000000000000005406161832",
     "000000000000000000000000000002435181822",
     "000000000000000000000000000003186658930",
     "000000000000000000000000000013812644024",
     "000000000000000000000000000004304582750",
     "000000000000000000000000000016245579631",
     "000000000000000000000000000000846155832",
     "000000000000000000000000000017104730104",
     "000000000000000000000000000000078683044",
     "000000000000000000000000000010089828658",
     "000000000000000000000000000011138057315",
     "000000000000000000000000000005415825591",
     "000000000000000000000000000008639367528",
     "000000000000000000000000000003762634526",
     "000000000000000000000000000001505622629", };
  ubintvec mul1(mul1sv);

  // modadd1:
  std::vector<std::string>  modadd1sv = 
    {"00000000000000030685", "00000000000000147278",
     "00000000000000159267", "00000000000000163697",
     "00000000000000071473", "00000000000000019606",
     "00000000000000091079", "00000000000000103742",
     "00000000000000097913", "00000000000000033395",
     "00000000000000038630", "00000000000000047611",
     "00000000000000154600", "00000000000000025200",
     "00000000000000160515", "00000000000000083430", };
  ubintvec modadd1(modadd1sv);

  // modsub1:
  std::vector<std::string>  modsub1sv = 
    {"00000000000000060980", "00000000000000008134",
     "00000000000000038840", "00000000000000045308",
     "00000000000000152791", "00000000000000035644",
     "00000000000000162467", "00000000000000077947",
     "00000000000000154031", "00000000000000135548",
     "00000000000000025203", "00000000000000012638",
     "00000000000000047306", "00000000000000129504",
     "00000000000000103511", "00000000000000030628", };
  ubintvec modsub1(modsub1sv);

  // modmul1:
  std::vector<std::string>  modmul1sv = 
    {"00000000000000069404", "00000000000000064196",
     "00000000000000013039", "00000000000000115321",
     "00000000000000028519", "00000000000000151998",
     "00000000000000089117", "00000000000000080908",
     "00000000000000057386", "00000000000000039364",
     "00000000000000008355", "00000000000000146135",
     "00000000000000061336", "00000000000000031598",
     "00000000000000025961", "00000000000000087680", };
  ubintvec modmul1(modmul1sv);

  ubintvec c1;
  mubintvec mc1;
  // test math for case 1
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1 + b1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 + b1) computation time: " << "\t" << time1 << " us");
  if (c1 != add1) {
    cout << "bad add" <<endl;
    vec_diff(c1, add1);
  }

  TIC(t1);

  for (usint j = 0; j< nloop; j++){
    c1 = a1 - b1;
  }

  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 - b1 computation time: " << "\t" << time1 << " us");
  if (c1 != sub1) {
    cout << "bad sub" <<endl;
    vec_diff(c1, sub1);
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1 * b1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1 * b1 computation time: " << "\t" << time1 << " us");
  if (c1 != mul1) {
    cout << "bad mul" <<endl;
    vec_diff(c1, mul1);
  }

  //now Mod operations
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModAdd(b1,q1);
    
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModAdd(b1,q1) computation time: " << "\t" << time1 << " us");
  if (c1 != modadd1){
    cout << "bad modadd" <<endl;
    vec_diff(c1, modadd1);
  }

  //now Mod operations
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    mc1 = ma1+mb1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops mc1 = ma1+mb1 computation time: " << "\t" << time1 << " us");
  if (ubintvec(mc1) != modadd1){
    cout << "bad modadd" <<endl;
    vec_diff(mc1, modadd1);
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModSub(b1,q1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModSub(b1,q1) computation time: " << "\t" << time1 << " us");

  if (c1 != modsub1) {
    cout << "bad modsub" <<endl;
    vec_diff(c1, modsub1);
  }
  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    mc1 = ma1 - mb1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops mc1 = ma1 - mb1 computation time: " << "\t" << time1 << " us");
  if (ubintvec(mc1) != modsub1){
    cout << "bad modsub" <<endl;
    vec_diff(mc1, modsub1);
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    c1 = a1.ModMul(b1,q1);
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops c1 = a1.ModMul(b1,q1)  computation time: " << "\t" << time1 << " us");
  if (c1 != modmul1) {
    cout << "bad mul" <<endl;
    vec_diff(c1, modmul1);
  }

  TIC(t1);
  for (usint j = 0; j< nloop; j++){
    mc1 = ma1*mb1;
  }
  time1 = TOC(t1);
  DEBUG("t1:  "<<nloop<<" loops mc1 = ma1*mb1 computation time: " << "\t" << time1 << " us");
  if (ubintvec(mc1) != modmul1){
    cout << "bad modmul" <<endl;
    vec_diff(mc1, modmul1);
  }

  // q2:

  ubint q2("00004057816419532801");
  //cout << "q2 contents"<<endl;
  //q2.PrintLimbsInDec();

  // a2:
  std::vector<std::string>  a2sv = 
    {"00000185225172798255", "00000098879665709163",
     "00003497410031351258", "00004012431933509255",
     "00001543020758028581", "00000135094568432141",
     "00003976954337141739", "00004030348521557120",
     "00000175940803531155", "00000435236277692967",
     "00003304652649070144", "00002032520019613814",
     "00000375749152798379", "00003933203511673255",
     "00002293434116159938", "00001201413067178193", };
  ubintvec a2(a2sv);
  mubintvec ma2(a2sv,q2);


  // b2:
  std::vector<std::string>  b2sv = 
    {"00000698898215124963", "00000039832572186149",
     "00001835473200214782", "00001041547470449968",
     "00001076152419903743", "00000433588874877196",
     "00002336100673132075", "00002990190360138614",
     "00000754647536064726", "00000702097990733190",
     "00002102063768035483", "00000119786389165930",
     "00003976652902630043", "00003238750424196678",
     "00002978742255253796", "00002124827461185795", };

  ubintvec b2(b2sv);
  mubintvec mb2(b2sv,q2);
  // add2:
  std::vector<std::string>  add2sv = 
    {"00000884123387923218", "00000138712237895312",
     "00005332883231566040", "00005053979403959223",
     "00002619173177932324", "00000568683443309337",
     "00006313055010273814", "00007020538881695734",
     "00000930588339595881", "00001137334268426157",
     "00005406716417105627", "00002152306408779744",
     "00004352402055428422", "00007171953935869933",
     "00005272176371413734", "00003326240528363988", };
  ubintvec add2(add2sv);
  // sub2:
#if 0 //set to 1 if we allow b>a in subtraction
  std::vector<std::string>  sub2sv = 
    {"18446230400667224908", "00000059047093523014",
     "00001661936831136476", "00002970884463059287",
     "00000466868338124838", "18446445579403106561",
     "00001640853664009664", "00001040158161418506",
     "18446165366977018045", "18446477211996511393",
     "00001202588881034661", "00001912733630447884",
     "18443143169959719952", "00000694453087476577",
     "18446058765570457758", "18445820659315544014", };

#else
  std::vector<std::string>  sub2sv = 
    {"00000000000000000000", "00000059047093523014",
     "00001661936831136476", "00002970884463059287",
     "00000466868338124838", "00000000000000000000",
     "00001640853664009664", "00001040158161418506",
     "00000000000000000000", "00000000000000000000",
     "00001202588881034661", "00001912733630447884",
     "00000000000000000000", "00000694453087476577",
     "00000000000000000000", "00000000000000000000", };

#endif
  ubintvec sub2(sub2sv);

  // mul2:
  std::vector<std::string>  mul2sv = 
    {"000000000129453542664913267883213339565",
     "000000000003938631422102517149330983287",
     "000000006419402382707574566639285895756",
     "000000004179138330699238739092142453840",
     "000000001660525522714165323210462878683",
     "000000000058575501928512376649634356636",
     "000000009290565704012341618368342178425",
     "000000012051509297159015143330318631680",
     "000000000132773293878034164433437538530",
     "000000000305578516062424854278036474730",
     "000000006946590599552827582889547919552",
     "000000000243468234057004000432166157020",
     "000000001494223959136453394722407100297",
     "000000012738664541883618180978992446890",
     "000000006831549111446250063725117624648",
     "000000002552795477367678807574345368435", };
  ubintvec mul2(mul2sv);

  // modadd2:
  std::vector<std::string>  modadd2sv = 
    {"00000884123387923218", "00000138712237895312",
     "00001275066812033239", "00000996162984426422",
     "00002619173177932324", "00000568683443309337",
     "00002255238590741013", "00002962722462162933",
     "00000930588339595881", "00001137334268426157",
     "00001348899997572826", "00002152306408779744",
     "00000294585635895621", "00003114137516337132",
     "00001214359951880933", "00003326240528363988", };
  ubintvec modadd2(modadd2sv);

  // modsub2:
  std::vector<std::string>  modsub2sv = 
    {"00003544143377206093", "00000059047093523014",
     "00001661936831136476", "00002970884463059287",
     "00000466868338124838", "00003759322113087746",
     "00001640853664009664", "00001040158161418506",
     "00003479109686999230", "00003790954706492578",
     "00001202588881034661", "00001912733630447884",
     "00000456912669701137", "00000694453087476577",
     "00003372508280438943", "00003134402025525199", };
  ubintvec modsub2(modsub2sv);

  // modmul2:
  std::vector<std::string>  modmul2sv = 
    {"00000585473140075497", "00003637571624495703",
     "00001216097920193708", "00001363577444007558",
     "00000694070384788800", "00002378590980295187",
     "00000903406520872185", "00000559510929662332",
     "00000322863634303789", "00001685429502680940",
     "00001715852907773825", "00002521152917532260",
     "00000781959737898673", "00002334258943108700",
     "00002573793300043944", "00001273980645866111", };
  ubintvec modmul2(modmul2sv);

  ubintvec c2;
  mubintvec mc2;
  // test math for case 2
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 + b2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 + b2) computation time: " << "\t" << time2 << " us");

  if (c2 != add2){
    cout << "bad add" <<endl;
    vec_diff(c2, add2);
  }
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 - b2;
  }
  //        c2.SetValAtIndex(14 , a2.GetValAtIndex(14) - b2.GetValAtIndex(14)); //OMG

  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 - b2 computation time: " << "\t" << time2 << " us");

  if (c2 != sub2) {
    cout << "bad sub" <<endl;
      vec_diff(c2, sub2);
  }
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2 * b2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2 * b2 computation time: " << "\t" << time2 << " us");
  if (c2 != mul2) {
    cout << "bad mul" <<endl;
    vec_diff(c2, mul2);
  }
  //now Mod operations
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModAdd(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModAdd(b2,q2) computation time: " << "\t" << time2 << " us");
  if (c2 != modadd2) {
    vec_diff(c2, modadd2);
  }
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    mc2 = ma2 + mb2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops mc2 = ma2 + mb2 computation time: " << "\t" << time2 << " us");
  if (ubintvec(mc2) != modadd2) {
    vec_diff(mc2, modadd2);
  }


  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModSub(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModSub(b2,q2) computation time: " << "\t" << time2 << " us");
  if (c2 != modsub2) {
    cout << "bad modsub" <<endl;
    vec_diff(c2, modsub2);   
  }

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    mc2 = ma2 - mb2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops mc2 = ma2 - mb2 computation time: " << "\t" << time2 << " us");
  if (ubintvec(mc2) != modsub2) {
    vec_diff(mc2, modsub2);
  }

  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    c2 = a2.ModMul(b2,q2);
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops c2 = a2.ModMul(b2,q2)  computation time: " << "\t" << time2 << " us");
  if (c2 != modmul2) {
    cout << "bad modmul" <<endl;
    vec_diff(c2, modmul2);   
  }
  TIC(t2);
  for (usint j = 0; j< nloop; j++){
    mc2 = ma2 * mb2;
  }
  time2 = TOC(t2);
  DEBUG("t2:  "<<nloop<<" loops mc2 = ma2 * mb2 computation time: " << "\t" << time2 << " us");
  if (ubintvec(mc2) != modmul2) {
    vec_diff(mc2, modmul2);
  }


  return ;
}

//the following code comes from http://www.hackersdelight.org/hdcodetxt/divmnu64.c.txt
//full rights to use are granted by the author

/* This divides an n-word dividend by an m-word divisor, giving an
   n-m+1-word quotient and m-word remainder. The bignums are in arrays of
   words. Here a "word" is 32 bits. This routine is designed for a 64-bit
   machine which has a 64/64 division instruction. */

#define max(x, y) ((x) > (y) ? (x) : (y))

int mynlz(usint x) {
  int n;

  if (x == 0) return(32);
  n = 0;
  if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
  if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
  if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
  if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
  if (x <= 0x7FFFFFFF) {n = n + 1;}
  return n;
}

void dumpit(char *msg, int n, usint v[]) {
  int i;
  printf(msg);
  for (i = n-1; i >= 0; i--) printf(" %08x", v[i]);
  printf("\n");
}

void dumpit_vect(char *msg, vector<usint> v) {
  int i;
  printf(msg);
  for (i = v.size()-1; i >= 0; i--) printf(" %08x", v[i]);
  printf("\n");
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
   (The sequence is in little-endian order).

   This is a fairly precise implementation of Knuth's Algorithm D, for a
   binary computer with base b = 2**32. The caller supplies:
   1. Space q for the quotient, m - n + 1 words (at least one).
   2. Space r for the remainder (optional), n words.
   3. The dividend u, m words, m >= 1.
   4. The divisor v, n words, n >= 2.
   The most significant digit of the divisor, v[n-1], must be nonzero.  The
   dividend u may have leading zeros; this just makes the algorithm take
   longer and makes the quotient contain more leading zeros.  A value of
   NULL may be given for the address of the remainder to signify that the
   caller does not want the remainder.
   The program does not alter the input parameters u and v.
   The quotient and remainder returned may have leading zeros.  The
   function itself returns a value of 0 for success and 1 for invalid
   parameters (e.g., division by 0).
   For now, we must have m >= n.  Knuth's Algorithm D also requires
   that the dividend be at least as long as the divisor.  (In his terms,
   m >= 0 (unstated).  Therefore m+n >= n.) */

int divmnu(usint q[], usint r[],
	   const usint u[], const usint v[],
	   int m, int n) {

  const uint64_t b = 4294967296LL; // Number base (2**32).
  usint *un, *vn;                  // Normalized form of u, v.
  uint64_t qhat;                   // Estimated quotient digit.
  uint64_t rhat;                   // A remainder.
  uint64_t p;                      // Product of two digits.
  int64_t t, k;
  int s, i, j;

  if (m < n || n <= 0 || v[n-1] == 0)
    return 1;                         // Return if invalid param.

  if (n == 1) {                        // Take care of
    k = 0;                            // the case of a
    for (j = m - 1; j >= 0; j--) {    // single-digit
      q[j] = (k*b + u[j])/v[0];      // divisor here.
      k = (k*b + u[j]) - q[j]*v[0];
    }
    if (r != NULL) r[0] = k;
    return 0;
  }

  /* Normalize by shifting v left just enough so that its high-order
     bit is on, and shift u left the same amount. We may have to append a
     high-order digit on the dividend; we do that unconditionally. */

  s = mynlz(v[n-1]);             // 0 <= s <= 31.
  vn = (usint *)alloca(4*n);
  for (i = n - 1; i > 0; i--)
    vn[i] = (v[i] << s) | ((uint64_t)v[i-1] >> (32-s));
  vn[0] = v[0] << s;

  un = (usint *)alloca(4*(m + 1));
  un[m] = (uint64_t)u[m-1] >> (32-s);
  for (i = m - 1; i > 0; i--)
    un[i] = (u[i] << s) | ((uint64_t)u[i-1] >> (32-s));
  un[0] = u[0] << s;

  for (j = m - n; j >= 0; j--) {       // Main loop.
    // Compute estimate qhat of q[j].
    qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
    rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
  again:
    if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
      { qhat = qhat - 1;
	rhat = rhat + vn[n-1];
	if (rhat < b) goto again;
      }

    // Multiply and subtract.
    k = 0;
    for (i = 0; i < n; i++) {
      p = qhat*vn[i];
      t = un[i+j] - k - (p & 0xFFFFFFFFLL);
      un[i+j] = t;
      k = (p >> 32) - (t >> 32);
    }
    t = un[j+n] - k;
    un[j+n] = t;

    q[j] = qhat;              // Store quotient digit.
    if (t < 0) {              // If we subtracted too
      q[j] = q[j] - 1;       // much, add back.
      k = 0;
      for (i = 0; i < n; i++) {
        t = (uint64_t)un[i+j] + vn[i] + k;
        un[i+j] = t;
        k = t >> 32;
      }
      un[j+n] = un[j+n] + k;
    }
  } // End j.
  // If the caller wants the remainder, unnormalize
  // it and pass it back.
  if (r != NULL) {
    for (i = 0; i < n-1; i++)
      r[i] = (un[i] >> s) | ((uint64_t)un[i+1] << (32-s));
    r[n-1] = un[n-1] >> s;
  }
  return 0;
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
   (The sequence is in little-endian order).

   This is a fairly precise implementation of Knuth's Algorithm D, for a
   binary computer with base b = 2**32. The caller supplies:
   1. Space q for the quotient, m - n + 1 words (at least one).
   2. Space r for the remainder (optional), n words.
   3. The dividend u, m words, m >= 1.
   4. The divisor v, n words, n >= 2.
   The most significant digit of the divisor, v[n-1], must be nonzero.  The
   dividend u may have leading zeros; this just makes the algorithm take
   longer and makes the quotient contain more leading zeros.  A value of
   NULL may be given for the address of the remainder to signify that the
   caller does not want the remainder.
   The program does not alter the input parameters u and v.
   The quotient and remainder returned may have leading zeros.  The
   function itself returns a value of 0 for success and 1 for invalid
   parameters (e.g., division by 0).
   For now, we must have m >= n.  Knuth's Algorithm D also requires
   that the dividend be at least as long as the divisor.  (In his terms,
   m >= 0 (unstated).  Therefore m+n >= n.) */

int divmnu_vect(vector <usint>& q, vector <usint>& r, const vector<usint>& u, const vector <usint>& v) {
  int m = u.size();
  int n = v.size();

  q.resize(m-n+1);
  r.resize(n);

  //const uint64_t b = 4294967296LL; // Number base (2**32).
  const uint64_t b = ULONG_MAX+1LL; // Number base (2**32).
  //   usint *un, *vn;                  // Normalized form of u, v.
  uint64_t qhat;                   // Estimated quotient digit.
  uint64_t rhat;                   // A remainder.
  uint64_t p;                      // Product of two digits.
  int64_t t, k;
  int s, i, j;

  if (m < n || n <= 0 || v[n-1] == 0)
    return 1;                         // Return if invalid param.

  if (n == 1) {                        // Take care of
    k = 0;                            // the case of a
    for (j = m - 1; j >= 0; j--) {    // single-digit
      q[j] = (k*b + u[j])/v[0];      // divisor here.
      k = (k*b + u[j]) - q[j]*v[0];
    }
    if (r.size() != 0) r[0]=k;
    return 0;
  }

  /* Normalize by shifting v left just enough so that its high-order
     bit is on, and shift u left the same amount. We may have to append a
     high-order digit on the dividend; we do that unconditionally. */

  s = mynlz(v[n-1]);             // 0 <= s <= 31.
  // vn = (usint *)alloca(4*n);
  vector<usint> vn(n);
  for (i = n - 1; i > 0; i--)
    vn[i] = (v[i] << s) | ((uint64_t)v[i-1] >> (32-s));
  vn[0] = v[0] << s;

  //un = (usint *)alloca(4*(m + 1));
  vector<usint> un(m+1);

  un[m] = (uint64_t)u[m-1] >> (32-s);
  for (i = m - 1; i > 0; i--)
    un[i] = (u[i] << s) | ((uint64_t)u[i-1] >> (32-s));
  un[0] = u[0] << s;

  for (j = m - n; j >= 0; j--) {       // Main loop.
    // Compute estimate qhat of q[j].
    qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
    rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
  again:
    if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
      { qhat = qhat - 1;
	rhat = rhat + vn[n-1];
	if (rhat < b) goto again;
      }

    // Multiply and subtract.
    k = 0;
    for (i = 0; i < n; i++) {
      p = qhat*vn[i];
      t = un[i+j] - k - (p & 0xFFFFFFFFLL);
      un[i+j] = t;
      k = (p >> 32) - (t >> 32);
    }
    t = un[j+n] - k;
    un[j+n] = t;

    q[j] = qhat;              // Store quotient digit.
    if (t < 0) {              // If we subtracted too
      q[j] = q[j] - 1;       // much, add back.
      k = 0;
      for (i = 0; i < n; i++) {
        t = (uint64_t)un[i+j] + vn[i] + k;
        un[i+j] = t;
        k = t >> 32;
      }
      un[j+n] = un[j+n] + k;
    }
  } // End j.
  // If the caller wants the remainder, unnormalize
  // it and pass it back.
  if (r.size() != 0) {
    r.resize(n);
    for (i = 0; i < n-1; i++)
      r[i] = (un[i] >> s) | ((uint64_t)un[i+1] << (32-s));
    r[n-1] = un[n-1] >> s;
  }
  return 0;
}

int errors;

void check(usint q[], usint r[],
	   usint u[], usint v[],
	   int m, int n,
	   usint cq[], usint cr[]) {
  int i, szq;

  szq = max(m - n + 1, 1);
  for (i = 0; i < szq; i++) {
    if (q[i] != cq[i]) {
      errors = errors + 1;
      dumpit("Error, dividend u =", m, u);
      dumpit("       divisor  v =", n, v);
      dumpit("For quotient,  got:", m-n+1, q);
      dumpit("        Should get:", m-n+1, cq);
      return;
    }
  }
  for (i = 0; i < n; i++) {
    if (r[i] != cr[i]) {
      errors = errors + 1;
      dumpit("Error, dividend u =", m, u);
      dumpit("       divisor  v =", n, v);
      dumpit("For remainder, got:", n, r);
      dumpit("        Should get:", n, cr);
      return;
    }
  }
  return;
}
void check_vect(vector<usint> q, vector<usint> r,
		vector<usint> u, vector<usint> v,
		usint cq[], usint cr[]) {
  int m = u.size();
  int n = v.size();

  int i, szq;

  szq = max(m - n + 1, 1);
  for (i = 0; i < szq; i++) {
    if (q[i] != cq[i]) {
      errors = errors + 1;
      dumpit_vect("Error, dividend u =", u);
      dumpit_vect("       divisor  v =", v);
      dumpit_vect("For quotient,  got:",  q);
      dumpit("        Should get:", m-n+1, cq);
      return;
    }
  }
  for (i = 0; i < n; i++) {
    if (r[i] != cr[i]) {
      errors = errors + 1;
      dumpit_vect("Error, dividend u =", u);
      dumpit_vect("       divisor  v =", v);
      dumpit_vect("For remainder, got:", r);
      dumpit("        Should get:", n, cr);
      return;
    }
  }
  return;
}

int divmain() {
  static usint test[] = {
    // m, n, u...,          v...,          cq...,  cr....
    1, 1, 3,             0,             1,      1,            // Error, divide by 0.
    1, 2, 7,             1,3,           0,      7,0,          // Error, n > m.
    2, 2, 0,0,           1,0,           0,      0,0,          // Error, incorrect remainder cr.
    1, 1, 3,             2,             1,      1,
    1, 1, 3,             3,             1,      0,
    1, 1, 3,             4,             0,      3,
    1, 1, 0,             0xffffffff,    0,      0,
    1, 1, 0xffffffff,    1,             0xffffffff, 0,
    1, 1, 0xffffffff,    0xffffffff,    1,      0,
    1, 1, 0xffffffff,    3,             0x55555555, 0,
    2, 1, 0xffffffff,0xffffffff, 1,     0xffffffff,0xffffffff, 0,
    2, 1, 0xffffffff,0xffffffff, 0xffffffff,        1,1,    0,
    2, 1, 0xffffffff,0xfffffffe, 0xffffffff,        0xffffffff,0, 0xfffffffe,
    2, 1, 0x00005678,0x00001234, 0x00009abc,        0x1e1dba76,0, 0x6bd0,
    2, 2, 0,0,           0,1,           0,      0,0,
    2, 2, 0,7,           0,3,           2,      0,1,
    2, 2, 5,7,           0,3,           2,      5,1,
    2, 2, 0,6,           0,2,           3,      0,0,
    1, 1, 0x80000000,  0x40000001, 0x00000001, 0x3fffffff,
    2, 1, 0x00000000,0x80000000, 0x40000001, 0xfffffff8,0x00000001, 0x00000008,
    2, 2, 0x00000000,0x80000000, 0x00000001,0x40000000, 0x00000001, 0xffffffff,0x3fffffff,
    2, 2, 0x0000789a,0x0000bcde, 0x0000789a,0x0000bcde,          1,          0,0,
    2, 2, 0x0000789b,0x0000bcde, 0x0000789a,0x0000bcde,          1,          1,0,
    2, 2, 0x00007899,0x0000bcde, 0x0000789a,0x0000bcde,          0, 0x00007899,0x0000bcde,
    2, 2, 0x0000ffff,0x0000ffff, 0x0000ffff,0x0000ffff,          1,          0,0,
    2, 2, 0x0000ffff,0x0000ffff, 0x00000000,0x00000001, 0x0000ffff, 0x0000ffff,0,
    3, 2, 0x000089ab,0x00004567,0x00000123, 0x00000000,0x00000001,   0x00004567,0x00000123, 0x000089ab,0,
    3, 2, 0x00000000,0x0000fffe,0x00008000, 0x0000ffff,0x00008000,   0xffffffff,0x00000000, 0x0000ffff,0x00007fff, // Shows that first qhat can = b + 1.
    3, 3, 0x00000003,0x00000000,0x80000000, 0x00000001,0x00000000,0x20000000,   0x00000003, 0,0,0x20000000, // Adding back step req'd.
    3, 3, 0x00000003,0x00000000,0x00008000, 0x00000001,0x00000000,0x00002000,   0x00000003, 0,0,0x00002000, // Adding back step req'd.
    4, 3, 0,0,0x00008000,0x00007fff, 1,0,0x00008000,   0xfffe0000,0, 0x00020000,0xffffffff,0x00007fff,  // Add back req'd.
    4, 3, 0,0x0000fffe,0,0x00008000, 0x0000ffff,0,0x00008000, 0xffffffff,0, 0x0000ffff,0xffffffff,0x00007fff,  // Shows that mult-sub quantity cannot be treated as signed.
    4, 3, 0,0xfffffffe,0,0x80000000, 0x0000ffff,0,0x80000000, 0x00000000,1, 0x00000000,0xfffeffff,0x00000000,  // Shows that mult-sub quantity cannot be treated as signed.
    4, 3, 0,0xfffffffe,0,0x80000000, 0xffffffff,0,0x80000000, 0xffffffff,0, 0xffffffff,0xffffffff,0x7fffffff,  // Shows that mult-sub quantity cannot be treated as signed.
  };
  int i, n, m, ncases, f;
  usint q[10], r[10];
  usint *u, *v, *cq, *cr;

  printf("divmnu:\n");
  i = 0;
  ncases = 0;
  while (i < sizeof(test)/4) {
    m = test[i];
    n = test[i+1];
    u = &test[i+2];
    v = &test[i+2+m];
    cq = &test[i+2+m+n];
    cr = &test[i+2+m+n+max(m-n+1, 1)];

    vector <usint> uv(0);
    for (usint j=0; j <m;j++){
      uv.push_back(u[j]);
    }

    vector <usint> vv(0);
    for (usint j=0; j <n;j++){
      vv.push_back(v[j]);
    }

    vector <usint> qv(0);
    vector <usint> rv(1);
    f = divmnu(q, r, u, v, m, n);
    if (f) {
      dumpit("Error return code for dividend  u =", m, u);
      dumpit("                      divisor   v =", n, v);
      errors = errors + 1;
    }
    else
      check(q, r, u, v, m, n, cq, cr);

    f = divmnu_vect(qv, rv, uv, vv);
    if (f) {
      dumpit_vect("Error return code for dividend uu =", uv);
      dumpit_vect("                      divisor  vv =", vv);
      errors = errors + 1;
    }


    i = i + 2 + m + n + max(m-n+1, 1) + n;
    ncases = ncases + 1;
  }

  printf("%d errors out of %d cases; there should be 3.\n", errors, ncases);
  return 0;
}
