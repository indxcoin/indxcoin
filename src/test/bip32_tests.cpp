// Copyright (c) 2013-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("xq5hkUvViHArUQTUrzVj9Hnzi8A65fPvEcKgkH5GjxfNnSssZ5hrSG7TSE4gpz7PnpDSWBUaK7r8oRPiFaWptwWCf9CaSxiJCwhLm1vgJZegrBR",
     "xprFCrDeMcm2aTTgEK17NckuHLBrcjLGCdbANrkrrdh8hQK2os9cHZoKkkBWFfLfcswEedhG7eWn7XyWauLyyXzHv1HBhyoYp6dzpEAUGvGCR4z",
     0x80000000)
    ("xq5hkXBuhzUKZfaU1bdSM3fdbAGCQUxGcgohRtWAi43Vke59vN12rVeYZNR6cFg6Y87yWPm9BMPZY4ToDyUxqyEaj2fJebWZ8FbZGx4EcEPowY2",
     "xprFCtV4ML4VfiafNv8paNdYANHxwYtcai5B4UBkpj5FfbWKB9SnhoLQstXv2vh12bKCMgaxUwqeVtpPJfNhd8GUi5MhmrUh44LtXEoKi4QjuTW",
     1)
    ("xq5hkZN2un2CxNTXr3ft5JZWBu9rTrwNciXzNDB1JKpJhGsN9uWAaJ4rWwKL2L8fx4qKU7PBxmqfeexGpHDnKJQUQgVEwoMQbtbpugb1uDZi3d7",
     "xprFCvfBZ7cP4RTjDNBGJdXQm7BczvsiajoTznrbQzr4cEJXQgwvRbkiqTS9Syt4dX6EomLeHmS5abmoSbtvkU4TVEr9HdSR7p7kC37hEzfWxBp",
     0x80000002)
    ("xq5hkbyJxJr4fFJwiDTyKtxsYuBzh1ottG7yhkQgYf7Ts9EoZkhHP3uHRNsFaMKWPwGdpdUva9pH2bXFGcN52Px1U8e5XhKYgqfWdNW9zTV9v9C",
     "xprFCyGTbeSEmJK95XyMZDvn87DmE5kErHPTLL6GfL9Dn6fxpY93EMb9jtz5126gbkbjKEN2tEP111bhfodgLUyecLHoeEzyGkMgoJrusbhYEh1",
     2)
    ("xq5hkeChnjy1qiyvngwh2AAxSQMJmq6dWrSB9EHyocdwBaoQvrKeSpbecxLBFgJtojRNHwc6iAJE5LRMq2i57hPDBj7LSUsjX2ZLe4R18zcPn1o",
     "xprFD1VrS5ZBwmz8A1T5FV8s1cP5Ju2yUshemoyZvHfh6YEaBdmQJ8HWwUSzgLW94R1AP2VjW9cZuq3s8zY8XuWzoisr3V64pqBPxHL5P9njjFs",
     1000000000)
    ("xq5hkfvUGRaFxrN8K2j98hjgk7MJa4fwLMFCwUgY3u25PfBudyj2yErJt4VEtWDqezW5mdteDWE2cY7xRT76DYt42zGTK2HpKW8yT22vP9S7vPb",
     "xprFD3DcumAS4uNKgMEXN2hbKKP578cHJNWga4N8Aa3qJcd4tmAnpYYBCac4KCHLyL8EzRtzHWbWksaz9AYW4yXivgXPNyrHwjw7EctS8EoLApA",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("xq5hkUvViHArUQTUrc14FSsHAKsrKrYLvEaWRrs12uQCkpzjr4j3cQtPs8EHB6CNW4aQQjiNDnWJCVtxyNF428RMo4CXJtum3SC15PbnaVC37Vm",
     "xprFCrDeMcm2aTTgDvWSUmqBjXucrvUgtFqz4SYb9aRxfnRu6rAoTiaGBeM6bj7ioPVKtgSgrvyEPe1hgS561xNzXNbxAPsnxSYjPUnhdtPnqEA",
     0)
    ("xq5hkYCEyzroxRHZNsbMPEFAE8HNgpHbdD4nz2cNCiReqErhY3B2BgEU1xoXkZAGJ9aqd4CY61W3bajw8XfjuH7n8eroaweRwnLPCsiT1kkBYCH",
     "xprFCuVPdLSz4UHkkC6jcZD4oLK9DtDwbELGccHxKPTQkCHrnpcn2yvLLUvMBEPXSTLAJLgWkwNxpoRq2whuaEt3TbmMAaHrLviUWthG1DQH5j1",
     0xFFFFFFFF)
    ("xq5hkZMJEbtLLKTfYjoXogEohTxw5ZWWAhEV5Bgu87LRUyd5zLQUoZenE2b8MwQP3tBwQa85jrMetoAXoCY5gBbtroKS82GVJWbQ5Fz3rWcyYf4",
     "xprFCveSswUWSNTrv4Jv31CiGfzhcdSr8iVxhmNVEnNBPw4FF7rEesLeYYhwnasWAi4eCa1QXxabsovwUBSgJcVB2uCubJXC7SSjJg2nmZX2KMd",
     1)
    ("xq5hkcAGecsGVxkreMUfsLPNfQuAR6P1Gt9kPdBkyAzknryXfAGe75BV7vyWCjbWqktDzkadaVStXvUMszo6b62r88nLiJULX42c12f16w6Ac9Q",
     "xprFCyTRHxTSc1m41fz46fMHEcvvxAKMEuRE2CsM5r2WhpQguwiPxNsMST6KdP58CRGLWXN7HFezHMc9ntDqMW1Z3P2Cj53zxYR7nUTXFCKQoCE",
     0xFFFFFFFE)
    ("xq5hkdLJZaod7MiZwJiGbpCv2vbMKprNKrnFRKueVthAddEn7WbaCk7VeTLbqPj238QfxCEGNzWbaXoDXdxVGy9MqVUnzCnq5M81sFjadxLGrgy",
     "xprFCzdTCvPoDQimJdDeq9Apc8d7rtniHt3j3ubEcZivYafwNJ3L43oMxyTRG5oWpqed46eob5RyfjBjc1KCsSv3jDhNZ1bK6kSk84U3JzzdiD2",
     2)
    ("xq5hkehLX228dY2ogZuAKtLc1fyKitPUaBhL5VXXug3fGR6NBhw9NP3Fq2HbunoJAhmNUFSVev21UEpD251z74qG9kLNdNcv1iQkYYvmJWw9dXB",
     "xprFD1zVAMcJjb313tQYZDJWat16FxKpYCxoi5D82M5RBNXXSVNuDgj89YQRLVUWyrjh6QWXsq4o7q2ReZCibmHGnCS6Ms6pAAaTpRobPfhCEr1",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("xq5hkUvViHArUQTUqfTDmqN5NK8tCVsSg6jn9CdZSCRm2X5XpJxKGZ8MpPTof5jMKfA3apUE3nPJbAipQfsxrqToDPrfS8oymzdqs77V74RjfV7",
     "xprFCrDeMcm2aTTgCyxc1AKywXAejZone81FmnK9YsTWwUWh56Q57rpE8uad5iqtkQieyP7SRrfLJ4kR35gQFPXRJr7CggSS9sthgCT4HmLw3M1",
      0x80000000)
    ("xq5hkXHhTEzz9mpq3CYczyhaRZtYtrUppx9gYgsWFS7bxpzu5L5mr3uDtrFWxoZs41knnBy4pk93S7vK38pJo5Pyne8c7EksKr8eMHUPmRSTmye",
     "xprFCtar6abAFpq2QX41EJfUzmvKRvRAnyRABGZ6N79MsnS4L7XXhMb6DNNLPVCF6N3aRXkrSoTCwoNsgdKYpc7B4cJq7pMUu3AWoDQiFCrxLBv",
      0);

TestVector test4 =
  TestVector("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
    ("xq5hkUvViHArUQTUsixncZitB4bmpjTcbM9XPLKxow7Lu3vDfCmeUTj82c1uMCz2M6k7AMbnCTcVXwVZDYf6H3UiJFiaCZ74LJbemhniBokMJc8",
     "xprFCrDeMcm2aTTgF3UAqtgnkGdYMoPxZNR11v1Yvc96p1MNuzDQKmQzM88imt81m97qYr54Y3YUEPxBg6JguUnLPfmbBvJUCknMxLKD3zuLtP1",
     0x80000000)
    ("xq5hkY5c6fHWrAZvWbyvEtefBThYGfLtJeg58dwd9uHKYVzC9jpm2o9rAehFWoFnNj7EaTN99W178sRokUM9ypw7PZmcEsY2D7h2pWLkzBt24dC",
     "xprFCuNkjzsgxDa7svVJUDcZkfjJojHEGfwYmDdDGaK5TTRMQXGWt6qiVAp4wS3FoxJCWq6W4cihYr4GckVnWrSyQJeX3Jc9QgEMwbM1npNfsUZ",
     0x80000001)
    ("xq5hkaDHkegXMtcXBkqZPAZZHLHPSbWxoaNsnZzSveoXCh5dvq9GuHdZPmf8Qk2KDujvAEyW3GwDbKmnixg4SRkG6rhyafP5ArAygvhf3pYScM6",
     "xprFCwWSPzGhTwciZ5LwcVXTrYK9yfTJmbeMR9g33KqH7eWoBcb2kbKRiHmwqQ1LsML2bbVcFDYfKVA9KiKVunQ6gh7kHeKAWiUgoGthtNnmA4i",
     0);

static void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed.data(), seed.size());
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK(EncodeExtKey(key) == derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK(EncodeExtPubKey(pubkey) == derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_CASE(bip32_test4) {
    RunTest(test4);
}

BOOST_AUTO_TEST_SUITE_END()
