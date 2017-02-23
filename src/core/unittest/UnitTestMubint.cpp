/**
 *  @file
 *  PRE SCHEME PROJECT, Crypto Lab, NJIT 
 *  @version v01.0
 *  @author TPOC: Dr. Kurt Rohloff, <rohloff@njit.edu> 
 *  Programmers: 
 *  Dr. Yuriy Polyakov, <polyakov@njit.edu>
 *  Gyana Sahu, <grs22@njit.edu> 
 *  Dr. David Bruce Cousins, <dcousins@bbn.com>
 *
 *  @section LICENSE
 *
 *  Copyright (c) 2015, New Jersey Institute of Technology (NJIT) All
 *  rights reserved.  Redistribution and use in source and binary forms,
 *  with or without modification, are permitted provided that the
 *  following conditions are met: 1. Redistributions of source code must
 *  retain the above copyright notice, this list of conditions and the
 *  following disclaimer.  2. Redistributions in binary form must
 *  reproduce the above copyright notice, this list of conditions and the
 *  following disclaimer in the documentation and/or other materials
 *  provided with the distribution.  THIS SOFTWARE IS PROVIDED BY THE
 *  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL uTHE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  @section DESCRIPTION
 *
 *  This file contains google test code that exercises the modulo big int
 *  vector library of the PALISADE lattice encryption library.
 *
 **/

//todo reduce the number of required includes
#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/
class UnitTestmubint : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Code here will be called before each test
    // (right before the constructor).

    //TODO: (dbc) do I need this here?
    // any calls to mubint may fail otherwise.
#if MATHBACKEND > 4 //mubint not defined before this. 
    NTL::ZZ_p::init(NTL::ZZ(1));
#endif
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/* list of tests left to run 
   //todo update this. 

  explicit mubint(const usint length, const bint_el_t & modulus);
  explicit mubint(const usint length, const std::string& modulus);
  explicit mubint(const std::vector<std::string> &s, const bint_el_t &modulus
  explicit mubint(const std::vector<std::string> &s, const std::string &modulus);

  void SetModulus(const uint& value);
  void SetModulus(const bint_el_t& value);
  void SetModulus(const std::string& value);
  const bint_el_t& GetModulus() const;

   //METHODS
   //todo write Div and /= vector scalar and vector vector
   
   Exp(const bint_el_t &b)

   GetDigitAtIndexForBase(usint index, usint base) const;
   
   //JSON FACILITY
   Serialize()
   Deserialize()
   

/************************************************/
/*	TESTING BASIC METHODS OF mubint CLASS        */
/************************************************/

#if MATHBACKEND > 4  //mubint not defined before this. 

TEST(UTmubint,ctor_access_eq_neq){
  //note this is the same code as the ubintvec, just to confirm it works
  //as inherited
  ubint q("1234567"); // a bigger number
  mubint m("9868");  

  m.SetModulus(q);
  mubint n("9868",q); // calling contructor with modulus

  //old fashioned way of expect
  EXPECT_EQ(9868U,m)
    << "Failure in SetValAtIndex(str)";

  EXPECT_EQ(ubint(9868U),m)<< "Failure in SetValAtIndex()";

  //new way of setting value of the value at different index locations
  n="4";
  EXPECT_EQ(ubint(4),n)<< "Failure in = string";
  n=9;   //int (implied)
  EXPECT_EQ(ubint(9),n)<< "Failure in = int";
  n=ubint("66"); //ubint
  EXPECT_EQ(ubint(66),n)<< "Failure in = ubint";
  n = 33L;  //long
  EXPECT_EQ(ubint(33),n)<< "Failure in = long";
  n = 7UL;  //unsigned long
  EXPECT_EQ(ubint(7),n)<< "Failure in = unsingned long";


  //test comparisons == and !=
  m = n;
  bool test1 = m==n;
  bool test2 = m!=n;
  EXPECT_TRUE(test1)<<"Failure ==";
  EXPECT_FALSE(test2)<<"Failure !=";

#if 0
  //we have only one modulus for mubint so this test will not work.

  //n.SetModulus(n.GetModulus()+ubint::ONE); //TODO:: this confused the compiler? //is operator+ inhereted and not operator- ?? that works below. 
  n.SetModulus(ubint(n.GetModulus()+ubint::ONE));
  //reset n to a differnt modulus, comparison will fail. 
  test1 = m==n;
  test2 = m!=n;

  cout<<"DEBUG: note the following fails right now since we are not testing moduli."<<endl;
  EXPECT_FALSE(test1)<<"Failure == different mods";

  cout<<"DEBUG: note the following fails right now since we are not testing moduli."<<endl;
  EXPECT_TRUE(test2)<<"Failure != different mods";
  // set it back 
  n.SetModulus(n.GetModulus()-ubint::ONE);

#endif


  m = n+n;
  test1 = m==n;
  test2 = m!=n;
  EXPECT_FALSE(test1)<<"Failure ==";
  EXPECT_TRUE(test2)<<"Failure !=";

  m = n;
  test1 = m==n;
  EXPECT_TRUE(test1)<<"Failure [] lhs rhs";

  //test more ctors

  ubint u = {"9872"}; //strings

  mubint u2(u);
  u2.SetModulus(q);
  mubint u3(u,q);
  mubint u4(u,"1234567"); 
  mubint u5(u,1234567U); 

  EXPECT_TRUE(u2 == u3) << "Failure ctor (ubint,ubint)";
  EXPECT_TRUE(u2 == u4) << "Failure ctor (ubint,string)";
  EXPECT_TRUE(u2 == u5) << "Failure ctor (ubint,usint)";

  //test comparison between ubint and mubint
  EXPECT_TRUE(u == u2) << "Failure mubint == ubintvec";

  EXPECT_FALSE(u != u2) << "Failure mubint == ubintvec";
  EXPECT_TRUE(u2 == u) << "Failure ubintvec == uubintvec";
  EXPECT_FALSE(u2 != u) << "Failure ubintvec == mubint";


}


TEST(UTmubint,mod){

  ubintvec n(10); // calling constructor to create a vector of length 10 zeroed
  mubint m;

  int i;
  usint j;
	
  //setting value of the value at different index locations
  n.SetValAtIndex(0,"987968");
  n.SetValAtIndex(1,"587679");
  n.SetValAtIndex(2,"456454");
  n.SetValAtIndex(3,"234343");
  n.SetValAtIndex(4,"769789");
  n.SetValAtIndex(5,"465654");
  n.SetValAtIndex(6,"79");
  n.SetValAtIndex(7,"346346");
  n.SetValAtIndex(8,"325328");
  n.SetValAtIndex(9,"7698798");	

  ubint q("233");		//calling costructor of ubint Class to create object for modulus
  //set modulus
  m.SetModulus(q); //should take modulus as well.
  usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array  

  for( auto i = 0; i < n.length(); i++) {
    m = n[i];
    mubint calculatedResult = m.Mod(q);
    EXPECT_EQ (expectedResult[i], calculatedResult)<<"Failure Mod, index"<< i;
  }
}

TEST(UTmubint,basic_mod_math_1_limb){

  // q1 modulus 1:
  ubint q1("163841");
  // a1:
  ubintvec a1(16);

  a1 = { "127753", "077706",
	 "017133", "022582",
	 "112132", "027625",
	 "126773", "008924",
	 "125972", "002551",
	 "113837", "112045",
	 "100953", "077352",
	 "132013", "057029", };

  // b1:
  ubintvec b1;
  b1 = {"066773", "069572",
	"142134", "141115",
	"123182", "155822",
	"128147", "094818",
	"135782", "030844",
	"088634", "099407",
	"053647", "111689",
	"028502", "026401", };
 
  // modadd1:
  ubintvec modadd1;
  modadd1 = {"030685", "147278",
	     "159267", "163697",
	     "071473", "019606",
	     "091079", "103742",
	     "097913", "033395",
	     "038630", "047611",
	     "154600", "025200",
	     "160515", "083430", };

  // modsub1:
  std::vector<std::string>  modsub1sv = 
    {"060980", "008134",
     "038840", "045308",
     "152791", "035644",
     "162467", "077947",
     "154031", "135548",
     "025203", "012638",
     "047306", "129504",
     "103511", "030628", };
  ubintvec modsub1(modsub1sv);

  // modmul1:
  std::vector<std::string>  modmul1sv = 
    {"069404", "064196",
     "013039", "115321",
     "028519", "151998",
     "089117", "080908",
     "057386", "039364",
     "008355", "146135",
     "061336", "031598",
     "025961", "087680", };
  ubintvec modmul1(modmul1sv);




  mubint a;
  a.SetModulus(q1);	// sets a.modulus to q1
  mubint b;
  b.SetModulus(q1);	// sets a.modulus to q1
  mubint c;
  c.SetModulus(a);	// sets c.modulus to the same as a

  mubint d;

  for (auto i = 0; i < a1.length(); i++) {
    a = a1[i];
    b= b1[i];
    //now Mod operations
    c = a.ModAdd(b);
    EXPECT_EQ (c, modadd1[i]) << "Failure 1 limb vector vector ModAdd() index "<<i;    
    // test math for case 1
    c = a.Add(b);
    EXPECT_EQ (c, modadd1[i]) << "Failure 1 limb vector vector Add() index "<<i;

    c = a + b;
    EXPECT_EQ (c, modadd1[i]) << "Failure 1 limb vector vector + index "<<i;

    d = a;
    d+=b;
    EXPECT_EQ (d, modadd1[i]) << "Failure 1 limb vector vector += index "<<i;
    c = a.ModSub(b);
    EXPECT_EQ (c, modsub1[i]) << "Failure 1 limb vector vector ModSub() index "<<i;   

    c = a.Sub(b);
    EXPECT_EQ (c, modsub1[i]) << "Failure 1 limb vector vector Sub() index "<<i;

    c = a - b;
    EXPECT_EQ (c, modsub1[i]) << "Failure 1 limb vector vector - index "<<i;

    d = a;
    d -= b;
    EXPECT_EQ (d, modsub1[i]) << "Failure 1 limb vector vector -= index "<<i;

    c = a.ModMul(b);
    EXPECT_EQ (c, modmul1[i]) << "Failure 1 limb vector vector ModMul() index "<<i;   

    c = a.Mul(b);
    EXPECT_EQ (c, modmul1[i]) << "Failure 1 limb vector vector Mul() index "<<i;

    c = a * b;
    EXPECT_EQ (c, modmul1[i]) << "Failure 1 limb vector vector * index "<<i;

    d = a;
    d *= b;
    EXPECT_EQ (d, modmul1[i]) << "Failure 1 limb vector vector *= index "<<i;
  }
}

TEST(UTmubint,basic_mod_math_2_limb){

  // q2 modulus 2:
  ubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  ubintvec a2(a2sv);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  ubintvec b2(b2sv);

  // modadd2:
  std::vector<std::string>  modadd2sv = 
    {"0884123387923218", "0138712237895312",
     "1275066812033239", "0996162984426422",
     "2619173177932324", "0568683443309337",
     "2255238590741013", "2962722462162933",
     "0930588339595881", "1137334268426157",
     "1348899997572826", "2152306408779744",
     "0294585635895621", "3114137516337132",
     "1214359951880933", "3326240528363988", };
  ubintvec modadd2(modadd2sv);

  // modsub2:
  std::vector<std::string>  modsub2sv = 
    {"3544143377206093", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "3759322113087746",
     "1640853664009664", "1040158161418506",
     "3479109686999230", "3790954706492578",
     "1202588881034661", "1912733630447884",
     "0456912669701137", "0694453087476577",
     "3372508280438943", "3134402025525199", };
  ubintvec modsub2(modsub2sv);

  // modmul2:
  std::vector<std::string>  modmul2sv = 
    {"0585473140075497", "3637571624495703",
     "1216097920193708", "1363577444007558",
     "0694070384788800", "2378590980295187",
     "0903406520872185", "0559510929662332",
     "0322863634303789", "1685429502680940",
     "1715852907773825", "2521152917532260",
     "0781959737898673", "2334258943108700",
     "2573793300043944", "1273980645866111", };
  ubintvec modmul2(modmul2sv);

  mubint a;
  a.SetModulus(q2);	// sets a.modulus to q2
  mubint b;
  b.SetModulus(q2);	// sets b.modulus
  mubint c;
  c.SetModulus(a);	// sets c.modulus to the same as a

  mubint d;
  for (auto i = 0; i < a2.length(); i++) {
    a = a2[i];
    b= b2[i];
    //now Mod operations
    c = a.ModAdd(b);
    EXPECT_EQ (c, modadd2[i]) << "Failure 2 limb vector vector ModAdd()index "<<i;    
    c = a.Add(b);
    EXPECT_EQ (c, modadd2[i]) << "Failure 2 limb vector vector Add()index "<<i;    

    c = a + b;
    EXPECT_EQ (c, modadd2[i]) << "Failure 2 limb vector vector +index "<<i;

    d = a;
    d += b;
    EXPECT_EQ (d, modadd2[i]) << "Failure 2 limb vector vector +=index "<<i;
  
    c = a.ModSub(b);
    EXPECT_EQ (c, modsub2[i]) << "Failure 2 limb vector vector ModSub()index "<<i;   
    c = a.Sub(b);
    EXPECT_EQ (c, modsub2[i]) << "Failure 2 limb vector vector Sub()index "<<i;    

    c = a - b;
    EXPECT_EQ (c, modsub2[i]) << "Failure 2 limb vector vector -index "<<i;

    d = a;
    d -= b;
    EXPECT_EQ (d, modsub2[i]) << "Failure 2 limb vector vector -=index "<<i;
  
    c = a.ModMul(b);
    EXPECT_EQ (c, modmul2[i]) << "Failure 2 limb vector vector ModMul()index "<<i;   
    c = a.Mul(b);
    EXPECT_EQ (c, modmul2[i]) << "Failure 2 limb vector vector Mul()index "<<i;    

    c = a * b;
    EXPECT_EQ (c, modmul2[i]) << "Failure 2 limb vector vector *index "<<i;

    d = a;
    d *= b;
    EXPECT_EQ (d, modmul2[i]) << "Failure 2 limb vector vector *=index "<<i;
  }
}




TEST(UTmubint,basic_mod_math_big_numbers){

  // q3:
  ubint q3("3273390607896141870013189696827599152216642046043064789483291368096133796404674554883270092325904157150886684127560071009217256545885393053328527589431");
  ubintvec a3;
  a3 = { 
    "2259002487796164904665772121894078584543401744155154298312726209247751689172189255653866355964200768484575418973864307364757237946940733747446643725054",
    "1478743816308009734668992873633380110912159803397999015955212019971253231528589466789603074746010444199132421555598329082557053986240265071537647362089",
    "2442250766561334341166822783674395133995556495312318016431141348749482739749788174173081312927274880146329980363424977565638001056841245678661782610982",
    "917779106114096279364098211126816308037915672568153320523308800097705587686270523428976942621563981845568821206569141624247183330715577260930218556767",
    "214744931049447103852875386182628152420432967632133352449560778740158135437968557572597545037670326240142368149137864407874100658923913041236510842284",
    "3022931024526554241483841300690432083112912011870712018209552253068347592628043101662926263810401378532416655773738499681026278335470355055192240903881",
    "2177879458107855257699914331737144896274676269055062432826552808869348125407671199582563543692287114712642299482144959316835614426673048987634699368975",
    "297233451802123294436846683552230198845414118375785255038220841170372509047202030175469239142902723134737621108313142071558385068315554041062888072990"};
  
  ubintvec b3;
  b3 = {
    "1746404952192586268381151521422372143182145525977836700420382237240400642889251297954418325675184427789348433626369450669892557208439401215109489355089",
    "220598825371098531288665964851212313477741334812037568788443848101743931352326362481681721872150902208420539619641973896119680592696228972313317042316",
    "1636408035867347783699588740469182350452165486745277203525427807971352063169622066488977229506420856017031482691439089288020262006748233954177669740311",
    "1391860681743495586446518646883933051685658718352722633694285758474124803847473349064660555618847951719510263829699292297119131926436045214364252430665",
    "840450278810654165061961485691366961514650606247291814263792869596294713810125269780258316551932763106025157596216051681623225968811609560121609943365",
    "2329731862150094912355786583702878434766436140738594274867891494713002534085652731920888891507522355867974791619686673574928137376468103839586921126803",
    "3059472316627396548271906051517665887700234192652488639437431254697285170484189458770168152800520702020313091234437806236204196526193455750117363744648",
    "132216870748476988853044482759545262615616157934129470128771906579101230690441206392939162889560305016204867157725209170345968349185675785497832527174"};


  ubintvec modadd3;
  modadd3 = {
    "732016832092609303033733946488851575508905224089926209249817078392018535656765998725014589313481039123037168472673687025432538609494741909227605490712",
    "1699342641679108265957658838484592424389901138210036584743655868072997162880915829271284796618161346407552961175240302978676734578936494043850964404405",
    "805268194532540254853221827315978332231079936014530430473277788624701006514735685778788450107791579012474778927303995844441006517704086579510924761862",
    "2309639787857591865810616858010749359723574390920875954217594558571830391533743872493637498240411933565079085036268433921366315257151622475294470987432",
    "1055195209860101268914836871873995113935083573879425166713353648336452849248093827352855861589603089346167525745353916089497326627735522601358120785649",
    "2079272278780507283826438187565711365662706106566241503594152379685216330309021278700545062992019577249504763265865102246737159166053065841450634441253",
    "1963961166839109935958630686427211631758268415664486282780692695470499499487186103469461604166903659582068706589022694543822554406981111684423535524192",
    "429450322550600283289891166311775461461030276309914725166992747749473739737643236568408402032463028150942488266038351241904353417501229826560720600164",
  };

  ubintvec modsub3;
  modsub3 = {
    "512597535603578636284620600471706441361256218177317597892343972007351046282937957699448030289016340695226985347494856694864680738501332532337154369965",
    "1258144990936911203380326908782167797434418468585961447166768171869509300176263104307921352873859541990711881935956355186437373393544036099224330319773",
    "805842730693986557467234043205212783543391008567040812905713540778130676580166107684104083420854024129298497671985888277617739050093011724484112870671",
    "2799309032266742562930769261070482408568899000258495476312314409719714580243471729247586479328620187276945241504429920336345307950164925099894493715533",
    "2647685260134934808804103597318860343122424407427906327669059277239997218032517842675609320811641720285003894680481883735468131235997696534443428488350",
    "693199162376459329128054716987553648346475871132117743341660758355345058542390369742037372302879022664441864154051826106098140959002251215605319777078",
    "2391797749376600579441197977047078160791084122445638582872412922268196751328156295695665483217670569843215892375267224089848674446364986290845863213758",
    "165016581053646305583802200792684936229797960441655784909448934591271278356760823782530076253342418118532753950587932901212416719129878255565055545816",
  };

  ubintvec modmul3;
    modmul3 = {
    "1031054745145843056820705945780914118282144310817341310210020640625431998591940403233545109350272933868060509405157360000389345101372898822036359679625",
    "39893990336327654775086201222472749396440031633689107793562292818341559091551650098949141027412374031231642492390533436782802979527602128674296589001",
    "1281575364673380787247887100773933340217543950815953588352031340354110014040347164387450177246143958852636145466379632479296531828035602618716943463922",
    "8876626876958332707488109358602242636976932642794865821404042110211562924605397999217054754859843534043902943791892973269404255881395585577402022234",
    "1216222886905600696846574145744495331189790230286057979942862366975568127231919204120976315097923349074161373380531458334894968146858459205019035261534",
    "753004725575957473234700352714317139479193934162886068369016394155680048439319699359431951178436867519868720662245420487511271148333130090416613227734",
    "2781700410947724700353568488987777429973246834920346616320143955645243949889536315043352628634199412806795883041065539549687937536501039961931401092055",
    "477574462920419903543345320561430691498452711801747910227743781056369739411065806345235440677935972019383967954633150768168291144898135169751571023658",
  };

  mubint a;
  a.SetModulus(q3);	// sets a.modulus to q3
  mubint b;
  b.SetModulus(q3);	// sets b.modulus
  mubint c;
  c.SetModulus(a);	// sets c.modulus to the same as a

  mubint d;
  for (auto i = 0; i < a3.length(); i++) {
    a = a3[i];
    b= b3[i];

    //now Mod operations
    c = a.ModAdd(b);
    EXPECT_EQ (c, modadd3[i]) << "Failure big number vector vector ModAdd()index "<<i;    

    c = a.Add(b);
    EXPECT_EQ (c, modadd3[i]) << "Failure big number vector vector Add()index "<<i;

    c = a + b;
    EXPECT_EQ (c, modadd3[i]) << "Failure big number vector vector +index "<<i;

    d = a;
    d+=b;
    EXPECT_EQ (d, modadd3[i]) << "Failure big number vector vector +=index "<<i;
  
    c = a.ModSub(b);
    EXPECT_EQ (c, modsub3[i]) << "Failure big number vector vector ModSub()index "<<i;   
  
    c = a.Sub(b);
    EXPECT_EQ (c, modsub3[i]) << "Failure big number vector vector Sub()index "<<i;

    c = a - b;
    EXPECT_EQ (c, modsub3[i]) << "Failure big number vector vector -index "<<i;

    d = a;
    d -= b;
    EXPECT_EQ (d, modsub3[i]) << "Failure big number vector vector -=index "<<i;

    c = a.ModMul(b);
    EXPECT_EQ (c, modmul3[i]) << "Failure big number vector vector ModMul()index "<<i;   

    c = a.Mul(b);
    EXPECT_EQ (c, modmul3[i]) << "Failure big number vector vector Mul()index "<<i;

    c = a * b;
    EXPECT_EQ (c, modmul3[i]) << "Failure big number vector vector *index "<<i;

    d = a;
    d *= b;
    EXPECT_EQ (d, modmul3[i]) << "Failure big number vector vector *=index "<<i;
  }
}

#endif
