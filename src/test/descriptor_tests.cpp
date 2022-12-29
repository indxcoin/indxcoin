// Copyright (c) 2018-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

namespace {

void CheckUnparsable(const std::string& prv, const std::string& pub, const std::string& expected_error)
{
    FlatSigningProvider keys_priv, keys_pub;
    std::string error;
    auto parse_priv = Parse(prv, keys_priv, error);
    auto parse_pub = Parse(pub, keys_pub, error);
    BOOST_CHECK_MESSAGE(!parse_priv, prv);
    BOOST_CHECK_MESSAGE(!parse_pub, pub);
    BOOST_CHECK_EQUAL(error, expected_error);
}

/** Check that the script is inferred as non-standard */
void CheckInferRaw(const CScript& script)
{
    FlatSigningProvider dummy_provider;
    std::unique_ptr<Descriptor> desc = InferDescriptor(script, dummy_provider);
    BOOST_CHECK(desc->ToString().rfind("raw(", 0) == 0);
}

constexpr int DEFAULT = 0;
constexpr int RANGE = 1; // Expected to be ranged descriptor
constexpr int HARDENED = 2; // Derivation needs access to private keys
constexpr int UNSOLVABLE = 4; // This descriptor is not expected to be solvable
constexpr int SIGNABLE = 8; // We can sign with this descriptor (this is not true when actual BIP32 derivation is used, as that's not integrated in our signing code)
constexpr int DERIVE_HARDENED = 16; // The final derivation is hardened, i.e. ends with *' or *h

/** Compare two descriptors. If only one of them has a checksum, the checksum is ignored. */
bool EqualDescriptor(std::string a, std::string b)
{
    bool a_check = (a.size() > 9 && a[a.size() - 9] == '#');
    bool b_check = (b.size() > 9 && b[b.size() - 9] == '#');
    if (a_check != b_check) {
        if (a_check) a = a.substr(0, a.size() - 9);
        if (b_check) b = b.substr(0, b.size() - 9);
    }
    return a == b;
}

std::string UseHInsteadOfApostrophe(const std::string& desc)
{
    std::string ret = desc;
    while (true) {
        auto it = ret.find('\'');
        if (it == std::string::npos) break;
        ret[it] = 'h';
    }

    // GetDescriptorChecksum returns "" if the checksum exists but is bad.
    // Switching apostrophes with 'h' breaks the checksum if it exists - recalculate it and replace the broken one.
    if (GetDescriptorChecksum(ret) == "") {
        ret = ret.substr(0, desc.size() - 9);
        ret += std::string("#") + GetDescriptorChecksum(ret);
    }
    return ret;
}

const std::set<std::vector<uint32_t>> ONLY_EMPTY{{}};

void DoCheck(const std::string& prv, const std::string& pub, const std::string& norm_prv, const std::string& norm_pub, int flags, const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type, const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY,
    bool replace_apostrophe_with_h_in_prv=false, bool replace_apostrophe_with_h_in_pub=false)
{
    FlatSigningProvider keys_priv, keys_pub;
    std::set<std::vector<uint32_t>> left_paths = paths;
    std::string error;

    std::unique_ptr<Descriptor> parse_priv;
    std::unique_ptr<Descriptor> parse_pub;
    // Check that parsing succeeds.
    if (replace_apostrophe_with_h_in_prv) {
        parse_priv = Parse(UseHInsteadOfApostrophe(prv), keys_priv, error);
    } else {
        parse_priv = Parse(prv, keys_priv, error);
    }
    if (replace_apostrophe_with_h_in_pub) {
        parse_pub = Parse(UseHInsteadOfApostrophe(pub), keys_pub, error);
    } else {
        parse_pub = Parse(pub, keys_pub, error);
    }

    BOOST_CHECK(parse_priv);
    BOOST_CHECK(parse_pub);

    // Check that the correct OutputType is inferred
    BOOST_CHECK(parse_priv->GetOutputType() == type);
    BOOST_CHECK(parse_pub->GetOutputType() == type);

    // Check private keys are extracted from the private version but not the public one.
    BOOST_CHECK(keys_priv.keys.size());
    BOOST_CHECK(!keys_pub.keys.size());

    // Check that both versions serialize back to the public version.
    std::string pub1 = parse_priv->ToString();
    std::string pub2 = parse_pub->ToString();
    BOOST_CHECK(EqualDescriptor(pub, pub1));
    BOOST_CHECK(EqualDescriptor(pub, pub2));

    // Check that both can be serialized with private key back to the private version, but not without private key.
    std::string prv1;
    BOOST_CHECK(parse_priv->ToPrivateString(keys_priv, prv1));
    BOOST_CHECK(EqualDescriptor(prv, prv1));
    BOOST_CHECK(!parse_priv->ToPrivateString(keys_pub, prv1));
    BOOST_CHECK(parse_pub->ToPrivateString(keys_priv, prv1));
    BOOST_CHECK(EqualDescriptor(prv, prv1));
    BOOST_CHECK(!parse_pub->ToPrivateString(keys_pub, prv1));

    // Check that private can produce the normalized descriptors
    std::string norm1;
    BOOST_CHECK(parse_priv->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK(EqualDescriptor(norm1, norm_pub));
    BOOST_CHECK(parse_pub->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK(EqualDescriptor(norm1, norm_pub));

    // Check whether IsRange on both returns the expected result
    BOOST_CHECK_EQUAL(parse_pub->IsRange(), (flags & RANGE) != 0);
    BOOST_CHECK_EQUAL(parse_priv->IsRange(), (flags & RANGE) != 0);

    // * For ranged descriptors,  the `scripts` parameter is a list of expected result outputs, for subsequent
    //   positions to evaluate the descriptors on (so the first element of `scripts` is for evaluating the
    //   descriptor at 0; the second at 1; and so on). To verify this, we evaluate the descriptors once for
    //   each element in `scripts`.
    // * For non-ranged descriptors, we evaluate the descriptors at positions 0, 1, and 2, but expect the
    //   same result in each case, namely the first element of `scripts`. Because of that, the size of
    //   `scripts` must be one in that case.
    if (!(flags & RANGE)) assert(scripts.size() == 1);
    size_t max = (flags & RANGE) ? scripts.size() : 3;

    // Iterate over the position we'll evaluate the descriptors in.
    for (size_t i = 0; i < max; ++i) {
        // Call the expected result scripts `ref`.
        const auto& ref = scripts[(flags & RANGE) ? i : 0];
        // When t=0, evaluate the `prv` descriptor; when t=1, evaluate the `pub` descriptor.
        for (int t = 0; t < 2; ++t) {
            // When the descriptor is hardened, evaluate with access to the private keys inside.
            const FlatSigningProvider& key_provider = (flags & HARDENED) ? keys_priv : keys_pub;

            // Evaluate the descriptor selected by `t` in position `i`.
            FlatSigningProvider script_provider, script_provider_cached;
            std::vector<CScript> spks, spks_cached;
            DescriptorCache desc_cache;
            BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i, key_provider, spks, script_provider, &desc_cache));

            // Compare the output with the expected result.
            BOOST_CHECK_EQUAL(spks.size(), ref.size());

            // Try to expand again using cached data, and compare.
            BOOST_CHECK(parse_pub->ExpandFromCache(i, desc_cache, spks_cached, script_provider_cached));
            BOOST_CHECK(spks == spks_cached);
            BOOST_CHECK(script_provider.pubkeys == script_provider_cached.pubkeys);
            BOOST_CHECK(script_provider.scripts == script_provider_cached.scripts);
            BOOST_CHECK(script_provider.origins == script_provider_cached.origins);

            // Check whether keys are in the cache
            const auto& der_xpub_cache = desc_cache.GetCachedDerivedExtPubKeys();
            const auto& parent_xpub_cache = desc_cache.GetCachedParentExtPubKeys();
            if ((flags & RANGE) && !(flags & DERIVE_HARDENED)) {
                // For ranged, unhardened derivation, None of the keys in origins should appear in the cache but the cache should have parent keys
                // But we can derive one level from each of those parent keys and find them all
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.size() > 0);
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    CExtPubKey der;
                    xpub.Derive(der, i);
                    pubkeys.insert(der.pubkey);
                }
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    BOOST_CHECK(pubkeys.count(pk) > 0);
                }
            } else if (pub1.find("xq5h") != std::string::npos) {
                // For ranged, hardened derivation, or not ranged, but has an xpub, all of the keys should appear in the cache
                BOOST_CHECK(der_xpub_cache.size() + parent_xpub_cache.size() == script_provider_cached.origins.size());
                // Get all of the derived pubkeys
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_map_pair : der_xpub_cache) {
                    for (const auto& xpub_pair : xpub_map_pair.second) {
                        const CExtPubKey& xpub = xpub_pair.second;
                        pubkeys.insert(xpub.pubkey);
                    }
                }
                // Derive one level from all of the parents
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    pubkeys.insert(xpub.pubkey);
                    CExtPubKey der;
                    xpub.Derive(der, i);
                    pubkeys.insert(der.pubkey);
                }
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    BOOST_CHECK(pubkeys.count(pk) > 0);
                }
            } else {
                // No xpub, nothing should be cached
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.empty());
            }

            // Make sure we can expand using cached xpubs for unhardened derivation
            if (!(flags & DERIVE_HARDENED)) {
                // Evaluate the descriptor at i + 1
                FlatSigningProvider script_provider1, script_provider_cached1;
                std::vector<CScript> spks1, spk1_from_cache;
                BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i + 1, key_provider, spks1, script_provider1, nullptr));

                // Try again but use the cache from expanding i. That cache won't have the pubkeys for i + 1, but will have the parent xpub for derivation.
                BOOST_CHECK(parse_pub->ExpandFromCache(i + 1, desc_cache, spk1_from_cache, script_provider_cached1));
                BOOST_CHECK(spks1 == spk1_from_cache);
                BOOST_CHECK(script_provider1.pubkeys == script_provider_cached1.pubkeys);
                BOOST_CHECK(script_provider1.scripts == script_provider_cached1.scripts);
                BOOST_CHECK(script_provider1.origins == script_provider_cached1.origins);
            }

            // For each of the produced scripts, verify solvability, and when possible, try to sign a transaction spending it.
            for (size_t n = 0; n < spks.size(); ++n) {
                BOOST_CHECK_EQUAL(ref[n], HexStr(spks[n]));
                BOOST_CHECK_EQUAL(IsSolvable(Merge(key_provider, script_provider), spks[n]), (flags & UNSOLVABLE) == 0);

                if (flags & SIGNABLE) {
                    CMutableTransaction spend;
                    spend.vin.resize(1);
                    spend.vout.resize(1);
                    BOOST_CHECK_MESSAGE(SignSignature(Merge(keys_priv, script_provider), spks[n], spend, 0, 1, SIGHASH_ALL), prv);
                }

                /* Infer a descriptor from the generated script, and verify its solvability and that it roundtrips. */
                auto inferred = InferDescriptor(spks[n], script_provider);
                BOOST_CHECK_EQUAL(inferred->IsSolvable(), !(flags & UNSOLVABLE));
                std::vector<CScript> spks_inferred;
                FlatSigningProvider provider_inferred;
                BOOST_CHECK(inferred->Expand(0, provider_inferred, spks_inferred, provider_inferred));
                BOOST_CHECK_EQUAL(spks_inferred.size(), 1U);
                BOOST_CHECK(spks_inferred[0] == spks[n]);
                BOOST_CHECK_EQUAL(IsSolvable(provider_inferred, spks_inferred[0]), !(flags & UNSOLVABLE));
                BOOST_CHECK(provider_inferred.origins == script_provider.origins);
            }

            // Test whether the observed key path is present in the 'paths' variable (which contains expected, unobserved paths),
            // and then remove it from that set.
            for (const auto& origin : script_provider.origins) {
                BOOST_CHECK_MESSAGE(paths.count(origin.second.second.path), "Unexpected key path: " + prv);
                left_paths.erase(origin.second.second.path);
            }
        }
    }

    // Verify no expected paths remain that were not observed.
    BOOST_CHECK_MESSAGE(left_paths.empty(), "Not all expected key paths found: " + prv);
}

void Check(const std::string& prv, const std::string& pub, const std::string& norm_prv, const std::string& norm_pub, int flags, const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type, const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY)
{
    bool found_apostrophes_in_prv = false;
    bool found_apostrophes_in_pub = false;

    // Do not replace apostrophes with 'h' in prv and pub
    DoCheck(prv, pub, norm_prv, norm_pub, flags, scripts, type, paths);

    // Replace apostrophes with 'h' in prv but not in pub, if apostrophes are found in prv
    if (prv.find('\'') != std::string::npos) {
        found_apostrophes_in_prv = true;
        DoCheck(prv, pub, norm_prv, norm_pub, flags, scripts, type, paths, /* replace_apostrophe_with_h_in_prv = */true, /*replace_apostrophe_with_h_in_pub = */false);
    }

    // Replace apostrophes with 'h' in pub but not in prv, if apostrophes are found in pub
    if (pub.find('\'') != std::string::npos) {
        found_apostrophes_in_pub = true;
        DoCheck(prv, pub, norm_prv, norm_pub, flags, scripts, type, paths, /* replace_apostrophe_with_h_in_prv = */false, /*replace_apostrophe_with_h_in_pub = */true);
    }

    // Replace apostrophes with 'h' both in prv and in pub, if apostrophes are found in both
    if (found_apostrophes_in_prv && found_apostrophes_in_pub) {
        DoCheck(prv, pub, norm_prv, norm_pub, flags, scripts, type, paths, /* replace_apostrophe_with_h_in_prv = */true, /*replace_apostrophe_with_h_in_pub = */true);
    }
}

}

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_test)
{
    // Basic single-key compressed
    Check("combo(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "combo(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "combo(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "combo(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", SIGNABLE, {{"21028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bccac","76a914eb7ea6edeaf8bd2d49d4b57d31437dd03eb2cb8d88ac","0014eb7ea6edeaf8bd2d49d4b57d31437dd03eb2cb8d","a914eadb3d5ad1710d8ed5b1ce33cad72e5edebb7bf787"}}, std::nullopt);
    Check("pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", SIGNABLE, {{"21028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bccac"}}, std::nullopt);
    Check("pkh([deadbeef/1/2'/3/4']a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pkh([deadbeef/1/2'/3/4']028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "pkh([deadbeef/1/2'/3/4']a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pkh([deadbeef/1/2'/3/4']028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", SIGNABLE, {{"76a914eb7ea6edeaf8bd2d49d4b57d31437dd03eb2cb8d88ac"}}, OutputType::LEGACY, {{1,0x80000002UL,3,0x80000004UL}});
    Check("wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", SIGNABLE, {{"0014eb7ea6edeaf8bd2d49d4b57d31437dd03eb2cb8d"}}, OutputType::BECH32);
    Check("sh(wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "sh(wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", SIGNABLE, {{"a914eadb3d5ad1710d8ed5b1ce33cad72e5edebb7bf787"}}, OutputType::P2SH_SEGWIT);
    CheckUnparsable("sh(wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxJ))", "sh(wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063b))", "Pubkey '028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063b' is invalid"); // Invalid pubkey
    CheckUnparsable("pkh(deadbeef/1/2'/3/4']a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pkh(deadbeef/1/2'/3/4']028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "Key origin start '[ character expected but not found, got 'd' instead"); // Missing start bracket in key origin
    CheckUnparsable("pkh([deadbeef]/1/2'/3/4']a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "pkh([deadbeef]/1/2'/3/4']028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "Multiple ']' characters found for a single pubkey"); // Multiple end brackets in key origin

    // Basic single-key uncompressed
    Check("combo(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "combo(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "combo(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "combo(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)",SIGNABLE, {{"41048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0ac","76a9146fc8fac81cbd2c7b02f61408f050130ac216ad9c88ac"}}, std::nullopt);
    Check("pk(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "pk(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "pk(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "pk(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", SIGNABLE, {{"41048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0ac"}}, std::nullopt);
    Check("pkh(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "pkh(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "pkh(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "pkh(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", SIGNABLE, {{"76a9146fc8fac81cbd2c7b02f61408f050130ac216ad9c88ac"}}, OutputType::LEGACY);
    CheckUnparsable("wpkh(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "wpkh(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("wsh(pk(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T))", "wsh(pk(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0))", "Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("sh(wpkh(8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T))", "sh(wpkh(048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0))", "Uncompressed keys are not allowed"); // No uncompressed keys in witness

    // Some unconventional single-key constructions
    Check("sh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "sh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", SIGNABLE, {{"a914a45d7974ebcb15981a90a2bd2bd0c74b5dcb02ce87"}}, OutputType::LEGACY);
    Check("sh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "sh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", SIGNABLE, {{"a914652d3a3b7df7affdeab15edd5f2c9cc02164b51087"}}, OutputType::LEGACY);
    Check("wsh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "wsh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "wsh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "wsh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", SIGNABLE, {{"0020afb42aa0da38de8f38f4db3d789e1a11064b984f0a1f62cd7f0aefb01aefb57f"}}, OutputType::BECH32);
    Check("wsh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "wsh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "wsh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "wsh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", SIGNABLE, {{"00206eac77e0ab82d876e5d5297b8a1ad3faab7112f804d7ec314ceee8731c3a08c4"}}, OutputType::BECH32);
    Check("sh(wsh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "sh(wsh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", "sh(wsh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "sh(wsh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", SIGNABLE, {{"a914571a92b4c3570cdd71d72ca5e9b39669e97406a587"}}, OutputType::P2SH_SEGWIT);
    Check("sh(wsh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "sh(wsh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", "sh(wsh(pkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "sh(wsh(pkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", SIGNABLE, {{"a914ca323c205bf295586e317c79c3e5566e5ba45fff87"}}, OutputType::P2SH_SEGWIT);

    // Versions with BIP32 derivations
    Check("combo([01234567]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6)", "combo([01234567]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT)", "combo([01234567]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6)", "combo([01234567]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT)", SIGNABLE, {{"21030b47430fbd1dfd98c931ca2098142d4eaf4852df6ea359f7da7f3141b1cd0027ac","76a914bf07017969432a842fd7c2744370ed6bb16ef9cb88ac","0014bf07017969432a842fd7c2744370ed6bb16ef9cb","a914d0f66cc8cfcc66848a656bd9e404dab0a69dbc2e87"}}, std::nullopt);
    Check("pk(xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0)", "pk(xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0)", "pk(xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0)", "pk(xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0)", DEFAULT, {{"2102f0666e85542d85c0dc52d10916027a1d74a7250cd89b9f9b45c1eab87b7247a1ac"}}, std::nullopt, {{0}});
    Check("pkh(xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0)", "pkh(xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0)", "pkh([4c1a67db/2147483647']xprFCrDeMcm2aTTgDmVj1GLvM9JWAdrhse9zUQ3MSQeqT6cu7wNvBtaLTKHemW56g6xez4JmHLMaisZPE23cTrajYJcXVES76sZ75woUyYTqRTK/0)", "pkh([4c1a67db/2147483647']xq5hkXN5JEioMzLreJXNfqF6LjmJUFyN1deQimU9ivt8Zt48wEhHwRTjdGALiXTAHXUjJGzX84idxoKnHKWzoCsrBoP7DZPJeaw2hVSCG9Tz99z/0)", HARDENED, {{"76a914a549e170e1603a9c53365cff772330e42a5299c888ac"}}, OutputType::LEGACY, {{0xFFFFFFFFUL,0}});
    Check("wpkh([ffffffff/13']xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*)", "wpkh([ffffffff/13']xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*)", "wpkh([ffffffff/13']xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*)", "wpkh([ffffffff/13']xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*)", RANGE, {{"00142cf657ea5bedd61afde78e77258cc54b310f767a"},{"0014ef5339d261660e01d67624752a453fc146257cc0"},{"0014422d6bf17b798a14d84462c0064103df2cf47e10"}}, OutputType::BECH32, {{0x8000000DUL, 1, 2, 0}, {0x8000000DUL, 1, 2, 1}, {0x8000000DUL, 1, 2, 2}});
    Check("sh(wpkh(xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "sh(wpkh(xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "sh(wpkh(xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "sh(wpkh(xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", RANGE | HARDENED | DERIVE_HARDENED, {{"a914dcc873a97dda90df5349a8cea42c61fbf6e9cee587"},{"a9147fa328221b5229489c70b65dd9a84becb84957e787"},{"a9144225f34b4206b74330e211165ffd8db12c8d48ae87"}}, OutputType::P2SH_SEGWIT, {{10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("combo(xprFCrDeMcm2aTTgDvfuZ1mStUz8zAxLMPXQSAn23W3VPcLLBDCSu8sPJD2NPKMP3B1peqVVYQF5KfsX5eFYtE73LVuFbG12iiW5x3CCjfuAipG/*)", "combo(xq5hkUvViHArUQTUrcAXKgoYKGxNT71zPNFvob6Rvq1jUeuAvRkh3qBWyguYxcFtYKcQatjKL4pJHsRh7u22vzQMjXkiUEeuNJRg9r2v3FJy9DM/*)", "combo(xprFCrDeMcm2aTTgDvfuZ1mStUz8zAxLMPXQSAn23W3VPcLLBDCSu8sPJD2NPKMP3B1peqVVYQF5KfsX5eFYtE73LVuFbG12iiW5x3CCjfuAipG/*)", "combo(xq5hkUvViHArUQTUrcAXKgoYKGxNT71zPNFvob6Rvq1jUeuAvRkh3qBWyguYxcFtYKcQatjKL4pJHsRh7u22vzQMjXkiUEeuNJRg9r2v3FJy9DM/*)", RANGE, {{"2103bf3a44aafb88959a8989cf76544e4f01381fcb5b6ef67b2e904b577814eb8aa8ac","76a914567f229947d50ddd27ae0b843eee88d102a8acf888ac","0014567f229947d50ddd27ae0b843eee88d102a8acf8","a914b6d04eb0f174500febb9b03f182e7cbd501b6d1d87"},{"2102aac685c5d5f3af2b061972674939f415012e91caa50b8d1da186186f6892d222ac","76a9142a84b2f8a82c86d9b6a3cdfa22b066486ad5920f88ac","00142a84b2f8a82c86d9b6a3cdfa22b066486ad5920f","a91450a7ce96f8518101286f8d055ae24deeda0c722087"}}, std::nullopt, {{0}, {1}});
    CheckUnparsable("combo([012345678]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6)", "combo([012345678]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT)", "Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long key fingerprint
    CheckUnparsable("pkh(xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483648)", "pkh(xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483648)", "Key path value 2147483648 is out of range"); // BIP 32 path element overflow
    CheckUnparsable("pkh(xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/1aa)", "pkh(xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/1aa)", "Key path value '1aa' is not a valid uint32"); // Path is not valid uint
    Check("pkh([01234567/10/20]xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0)", "pkh([01234567/10/20]xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0)", "pkh([01234567/10/20/2147483647']xprFCrDeMcm2aTTgDmVj1GLvM9JWAdrhse9zUQ3MSQeqT6cu7wNvBtaLTKHemW56g6xez4JmHLMaisZPE23cTrajYJcXVES76sZ75woUyYTqRTK/0)", "pkh([01234567/10/20/2147483647']xq5hkXN5JEioMzLreJXNfqF6LjmJUFyN1deQimU9ivt8Zt48wEhHwRTjdGALiXTAHXUjJGzX84idxoKnHKWzoCsrBoP7DZPJeaw2hVSCG9Tz99z/0)", HARDENED, {{"76a914a549e170e1603a9c53365cff772330e42a5299c888ac"}}, OutputType::LEGACY, {{10, 20, 0xFFFFFFFFUL, 0}});

    // Multisig constructions
    Check("multi(1,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "multi(1,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "multi(1,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "multi(1,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", SIGNABLE, {{"5121028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc41048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e052ae"}}, std::nullopt);
    Check("sortedmulti(1,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "sortedmulti(1,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "sortedmulti(1,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "sortedmulti(1,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", SIGNABLE, {{"5121028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc41048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e052ae"}}, std::nullopt);
    Check("sortedmulti(1,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "sortedmulti(1,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "sortedmulti(1,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "sortedmulti(1,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", SIGNABLE, {{"5121028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc41048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e052ae"}}, std::nullopt);
    Check("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))", "sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))", DEFAULT, {{"a914295a104d351d2ba07a4e26330da99bf840b5c4ae87"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    Check("sortedmulti(2,xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6/*,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0/0/*)", "sortedmulti(2,xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT/*,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0/0/*)", "sortedmulti(2,xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6/*,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0/0/*)", "sortedmulti(2,xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT/*,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0/0/*)", RANGE, {{"522103a611d3cbd1fdb8df1e8391b93b8352c41d39b333e68619f3fe19485934ad8df82103ce26a2552ba3f79e2bb2367cacd374fe19605522f3de2f74ab7f2277fa57daea52ae"}, {"5221023148e47507620f2520b074c6afb78f1e15e3ff81da18c85b99e204b949e496152103e7af8bd29c7900db8590883410e379ed4564de2c5e321aec86dca7f7edb947e852ae"}, {"522102307deb6072ad64123d144694cfa69479bc69d69354dbc68baf3ab6c98520e463210287cd18c8281813fe1fa7cc3754745168de96031276ccec256b6b54d34520ca4752ae"}}, std::nullopt, {{0}, {1}, {2}, {0, 0, 0}, {0, 0, 1}, {0, 0, 2}});
    Check("wsh(multi(2,xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "wsh(multi(2,[4c1a67db/2147483647']xprFCrDeMcm2aTTgDmVj1GLvM9JWAdrhse9zUQ3MSQeqT6cu7wNvBtaLTKHemW56g6xez4JmHLMaisZPE23cTrajYJcXVES76sZ75woUyYTqRTK/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[4c1a67db/2147483647']xq5hkXN5JEioMzLreJXNfqF6LjmJUFyN1deQimU9ivt8Zt48wEhHwRTjdGALiXTAHXUjJGzX84idxoKnHKWzoCsrBoP7DZPJeaw2hVSCG9Tz99z/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", HARDENED | RANGE | DERIVE_HARDENED, {{"00206ee97b7e65bd5d527ae72c586ccb60aaa97b0838abaf0c42592ed68ab85db419"},{"00202547dbe96e9c736c5516e297a8ce98aca2be54a55c2a7161d13e272165ad0337"},{"00207a642c6ce92643d02146e2b7e3d1b3ec26af839aa8675dc1652d4667c01939cb"}}, OutputType::BECH32, {{0xFFFFFFFFUL,0}, {1,2,0}, {1,2,1}, {1,2,2}, {10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("sh(wsh(multi(16,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz)))","sh(wsh(multi(16,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d)))", "sh(wsh(multi(16,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz)))","sh(wsh(multi(16,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d)))", SIGNABLE, {{"a914f8d18b15ec576d07a0dcb3f56a2e675a5e46801d87"}}, OutputType::P2SH_SEGWIT);
    CheckUnparsable("sh(multi(16,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz))","sh(multi(16,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d))", "P2SH script is too large, 547 bytes is larger than 520 bytes"); // P2SH does not fit 16 compressed pubkeys in a redeemscript
    CheckUnparsable("wsh(multi(2,[aaaaaaaa][aaaaaaaa]xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa][aaaaaaaa]xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "Multiple ']' characters found for a single pubkey"); // Double key origin descriptor
    CheckUnparsable("wsh(multi(2,[aaaagaaa]xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[aaagaaaa]xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "Fingerprint 'aaagaaaa' is not hex"); // Non hex fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaa],xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa],xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "No key provided"); // No public key with origin
    CheckUnparsable("wsh(multi(2,[aaaaaaa]xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaa]xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "Fingerprint is not 4 bytes (7 characters instead of 8 characters)"); // Too short fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaaa]xprFCrDeMcm2aTTgFUAmk5FPveAVQ5WW3nv7J6DRSoq7zvnN6s5NJp7ogSb3TkVjAF6UkzAazHnRqfRAWuwEhPvtpy8mMxbbVqQJeLC5EVM8tdS/2147483647'/0,xprFCrDeMcm2aTTgFJbZpDjK6h2j8c3GSVEwuvMxge3aV58qwHsFm91e1hWdsAcMbCSsE4vFeqAZeiSc4NoPbbeiZGAnZtzFNFnzcZZkJTCU1oB/1/2/*,xprFCrDeMcm2aTTgD7qGwaJh8ujD3rJ7FsHRCTHhAqgoB1t5M596kindMUJbwmiLzZ6bChrQT7GyzRMosZtiuXWUyvEgP3e1KFr2m8xPQdy6oE9/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaaa]xq5hkUvViHArUQTUt9fPWkHVMS8is1aA5medfWXqL8oN5yMCr5dcTWRwMvUE33twTgMz25pAFtA8s8WRWf7i1iDcGo1TTFYbWJv2UZdrMeahGE3/2147483647'/0,xq5hkUvViHArUQTUsz6BatmQXUzxbY6vUTyUHLgNZy1pa7hggWRVuqKmhBPpSUXMU5QXwf2WQyMduuLUYaMpxc4ecwrf5YP94rTtMnFccPYMMxe/1/2/*,xq5hkUvViHArUQTUqoKtiFLnZhhSWnMmHr1wZsc74Af3G4Sv6HhLuR6m2xBnX5Nof5LsFad9tuWhXyXWCS469PMBu8ShpcgJQRSVjfPdkbedhaZ/10/20/30/40/*'))", "Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long fingerprint
    CheckUnparsable("multi(a,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "multi(a,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "Multi threshold 'a' is not valid"); // Invalid threshold
    CheckUnparsable("multi(0,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "multi(0,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "Multisig threshold cannot be 0, must be at least 1"); // Threshold of 0
    CheckUnparsable("multi(3,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH,8W9Mfcx49CxW3bfcrUvkTnP8LGCvNn1LzjH28TY49A1iHiXA95T)", "multi(3,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc,048717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc1abe7bfa379401e4bc17c91d786847498c9fc8f25c49655c2b97e1b67830f6e0)", "Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified"); // Threshold larger than number of keys
    CheckUnparsable("multi(3,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o)", "multi(3,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164)", "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys"); // Threshold larger than number of keys
    CheckUnparsable("sh(multi(16,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz,a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))","sh(multi(16,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d,028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "P2SH script is too large, 581 bytes is larger than 520 bytes"); // Cannot have more than 15 keys in a P2SH multisig, or we exceed maximum push size
    Check("wsh(multi(20,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz,a7Ti1TMeYTtaUUjrmmXMEFXFaQ28oxTL9EmyfDyusRcewV3L6e75,a3DuLSjj6rzXzLdgNkL9vEVeSKFpDC4Ze5EgTDP12pk6Mm985P4J,ZzjrEFLKTyAViXoqGfkgxgzYRW9iac3A3tqBub65HqTqRMShh9PN,a5pXY5r4vjw7MS9e4bD31VGGgGnAa1cjDxExBaDiGTSeNMgHci3B))","wsh(multi(20,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d,02b5af6180634c95aaaf54ac466d9d881290d49d5b727b2b228c4b15d4381c43fc,0214be23457a1cb8c5aed397cf114c28f26f6412da590b032e7818a90cd69ad293,026976ecced12d82734662613d9caf662c210cacdc35ac251f88939700e413643c,03081e4fbf7e95c6c0bdb9d94e4bc31af23160b586ae8e7b8dc848dee556e22a4c))", "wsh(multi(20,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz,a7Ti1TMeYTtaUUjrmmXMEFXFaQ28oxTL9EmyfDyusRcewV3L6e75,a3DuLSjj6rzXzLdgNkL9vEVeSKFpDC4Ze5EgTDP12pk6Mm985P4J,ZzjrEFLKTyAViXoqGfkgxgzYRW9iac3A3tqBub65HqTqRMShh9PN,a5pXY5r4vjw7MS9e4bD31VGGgGnAa1cjDxExBaDiGTSeNMgHci3B))","wsh(multi(20,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d,02b5af6180634c95aaaf54ac466d9d881290d49d5b727b2b228c4b15d4381c43fc,0214be23457a1cb8c5aed397cf114c28f26f6412da590b032e7818a90cd69ad293,026976ecced12d82734662613d9caf662c210cacdc35ac251f88939700e413643c,03081e4fbf7e95c6c0bdb9d94e4bc31af23160b586ae8e7b8dc848dee556e22a4c))", SIGNABLE, {{"0020501e3070dd08112c408c82c92401b3501a707e3d51d458f4bd9d1a72e5755d8e"}}, OutputType::BECH32); // In P2WSH we can have up to 20 keys
Check("sh(wsh(multi(20,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz,a7Ti1TMeYTtaUUjrmmXMEFXFaQ28oxTL9EmyfDyusRcewV3L6e75,a3DuLSjj6rzXzLdgNkL9vEVeSKFpDC4Ze5EgTDP12pk6Mm985P4J,ZzjrEFLKTyAViXoqGfkgxgzYRW9iac3A3tqBub65HqTqRMShh9PN,a5pXY5r4vjw7MS9e4bD31VGGgGnAa1cjDxExBaDiGTSeNMgHci3B)))","sh(wsh(multi(20,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d,02b5af6180634c95aaaf54ac466d9d881290d49d5b727b2b228c4b15d4381c43fc,0214be23457a1cb8c5aed397cf114c28f26f6412da590b032e7818a90cd69ad293,026976ecced12d82734662613d9caf662c210cacdc35ac251f88939700e413643c,03081e4fbf7e95c6c0bdb9d94e4bc31af23160b586ae8e7b8dc848dee556e22a4c)))", "sh(wsh(multi(20,a3T2cPLEcCzpuAB3BE2PQ5LfHxX2WSnd5AcBRBskRUfw3mbdrvkx,a5WGuxcwSQzfzcKzGXyLXrP5zmDXqt8nGN5oxVRBWC8Fu2u7wWVd,a6fpUi3gktWnMPLscnaedufxyeGQfP9xAa3hrq7rdHoiyoRei7k8,a2BNCfHJLztfqmZXH6qyTJUHmmaBxLdpwRnqBN2MVXy8TmS4yn4o,a4cVkLWC5wWF3VAG9wmLbeRKedynSkUt99HWuMeLfo2WxrvRNsUA,a59hQQTDHZjWfWSRU6cEdnHs12fT9x6CGAkuL4YdPoqWzKnh2PRi,a41fKAhngLqfAz6SrLVMmosdTH6sA6rUBU4rVHpC83QECLcyyKRy,a68xkGethN3P6gBTpW4fy8UYvMs6NvcCamdEuYx7owcQNriDwGJ4,a68na45wjLKmTPfzzNEkufwJzC79azrSEghFVo4fkxXnJUC6RKHs,a7rKYuZjgqU7pqLt8CbtNd5z1L5gTrrdoiLfBABKsuqcc7xVrVkz,a7WJ5yRe4Mi19fr7eE6v1tFUUirZKXzwzvUBif7HSN5zD6HP21sE,a4HxYsACRdSDXDFvN1a8ffi69Kox5VGWqZWmBPLUQmSC452J9N3S,a3E1C9TXRxhM5Xda5V3pudhGKz8zj8ZACm9rama9TGbFmrGW98kn,a11Ht94wN7cFm38kioydBT7rebF7r7Xc5AJQ4uLAztxpfRD2NUea,a8YZBGCk9GdZSufXACoKpBoTcBudENqWfGUqFSnaAWUf45bzrFFL,a3JTS9ViFMe4VQhA3QzsmRnmPgpouRwea5JaVawJp8nu8h5uoBBz,a7Ti1TMeYTtaUUjrmmXMEFXFaQ28oxTL9EmyfDyusRcewV3L6e75,a3DuLSjj6rzXzLdgNkL9vEVeSKFpDC4Ze5EgTDP12pk6Mm985P4J,ZzjrEFLKTyAViXoqGfkgxgzYRW9iac3A3tqBub65HqTqRMShh9PN,a5pXY5r4vjw7MS9e4bD31VGGgGnAa1cjDxExBaDiGTSeNMgHci3B)))","sh(wsh(multi(20,02ab46b8258b30a77f040789774029d4bf84d5376a6576248a6f8236d022194cd8,039cd88b249e6f5c3db1101ba0a2b609a8eaab2036263f2432e39de041daed6acc,024c7fddbbec601c2e8099164b620d177d40a3353e2d6fefac1ec90883c6d0f6e5,0257a8cfe0211676d02c0cbfc13edaf2c69786d71f5c36102d6ab82b669fd3a164,0278d4e5443f9626f9be8948fafab69bf92d96303866141d9fd7bc3da2b6967906,0294723680d3cdbae8639070da7513ef2760178af55663eb7a0de1cab6747a1c8a,021717626806a6e648f92b6a68e13cc6627313018fa6113fc0c8b637f861f24e70,029e573308001ad9921ee96b3a45a72f1ade39887bbec6e7e14b82ffae7d37b242,024bbe7347638a7f1817b50ae0b048a93c7dc7187a82bfd32e9844b5c9f3d2cffa,02eadf0371277e6076bc4ab6e66b45b6a48321541521a0b3be6eea59021ea5d7ae,02e0ab9645b86d2fd940bea4f76d994f4d25d96bee7f3b548284421f62e9c589b3,03f21e0ddc026efd529ff9ad77104861a99cfa673b6c800718599e99ae3f95d7de,028cd45a32a9df43b30e238dcb4f7063e01069cc33c4203f295b36f9c47f8a90da,02c50b4d8c4c8a4114726015039848f46bc5a9b6d296216069fbf1e65f7f481dc8,02633445f22dbc7f0de170db2b8c3346007829279b90aa5d13c454e2567d12bb64,0208122ccf4a84b067ab9c3272ea5fb192a287a97b9139d06a635c555bdc1dcd2d,02b5af6180634c95aaaf54ac466d9d881290d49d5b727b2b228c4b15d4381c43fc,0214be23457a1cb8c5aed397cf114c28f26f6412da590b032e7818a90cd69ad293,026976ecced12d82734662613d9caf662c210cacdc35ac251f88939700e413643c,03081e4fbf7e95c6c0bdb9d94e4bc31af23160b586ae8e7b8dc848dee556e22a4c)))", SIGNABLE, {{"a914fe118f5f94f224a37b2c9d48aadeecbbadc7255887"}}, OutputType::P2SH_SEGWIT); // Even if it's wrapped into P2SH
    // Check for invalid nesting of structures
    CheckUnparsable("sh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "sh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "A function is needed within P2SH"); // P2SH needs a script, not a key
    CheckUnparsable("sh(combo(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "sh(combo(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "Can only have combo() at top level"); // Old must be top level
    CheckUnparsable("wsh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)", "wsh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)", "A function is needed within P2WSH"); // P2WSH needs a script, not a key
    CheckUnparsable("wsh(wpkh(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH))", "wsh(wpkh(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc))", "Can only have wpkh() at top level or inside sh()"); // Cannot embed witness inside witness
    CheckUnparsable("wsh(sh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "wsh(sh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2WSH
    CheckUnparsable("sh(sh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "sh(sh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2SH
    CheckUnparsable("wsh(wsh(pk(a7dtDTfzsDmyCU1TFQGEqDJfN27cb7eXFobhyv84rzn9EjBxPNxH)))", "wsh(wsh(pk(028717f6978b068451b87e1958d4a93e4cf4c945ea7cc8268ccd07002a85063bcc)))", "Can only have wsh() at top level or inside sh()"); // Cannot embed P2WSH inside P2WSH

    // Checksums
    Check("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#l0lsqrls", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#chdnsz9t", "sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0)#chdnsz9t", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#chdnsz9t", DEFAULT, {{"a914295a104d351d2ba07a4e26330da99bf840b5c4ae87"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    Check("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))", "sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))", DEFAULT, {{"a914295a104d351d2ba07a4e26330da99bf840b5c4ae87"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#", "Expected 8 character checksum, not 0 characters"); // Empty checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#xezmcsheq", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#yd7vdjzaq", "Expected 8 character checksum, not 9 characters"); // Too long checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#ggrsrxf", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#tjg09x5", "Expected 8 character checksum, not 7 characters"); // Too short checksum
    CheckUnparsable("sh(multi(3,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#xezmcshe", "sh(multi(3,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#yd7vdjza", "Provided checksum 'yd7vdjza' does not match computed checksum '7srnfz4v'"); // Error in payload
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))#ggssrxfy", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))#tjq09x4t", "Provided checksum 'tjq09x4t' does not match computed checksum 'chdnsz9t'"); // Error in checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprFCyUXy8y1sPVQi6iHFWMiujKY15H3Q9ostqJxsWXUNAAv6U6SKnhdFYfFg23LgqSjg2SujP8sw8fJZZkYBWwLHkRrGP1NPNEZuqbXLqFtDT6,xprFCrDeMcm2aTTgDmwBpaHR67M4MmuePsZysGxuvL1no41cNxGHj1jvZgKcmB3g98A6XnbiSf3FbqQ6E4TLHoBTLjjAgLgBtRVoBZP7FApJ6Sy/0))##ggssrxfy", "sh(multi(2,[00000000/111'/222]xq5hkcBPKoNqmLVDLnCu2BPpLXHmU1LhS8YQGFdNkqViTCjkqgegUV1kw2YSFMaQmiThakZ8DmWgteSWwFcKxLmx2g1y3wVU3y9kdEHV5imdjPT,xq5hkUvViHArUQTUrTRobFKWWuKHphyJRrJWEhHKoez2t6aT8ApXsi44FACoLVcWdebGhkZBCepzX4z2rjiGCpv3VQwj3NyPDDesjmheuVj9xw9/0))##tjq09x4t", "Multiple '#' symbols"); // Error in checksum

    // Addr and raw tests 
    CheckUnparsable("", "addr(asdf)", "Address is not valid"); // Invalid address
    CheckUnparsable("", "raw(asdf)", "Raw script is not hex"); // Invalid script
    CheckUnparsable("", "raw(Ü)#00000000", "Invalid characters in payload"); // Invalid chars

    // A 2of4 but using a direct push rather than OP_2
    CScript nonminimalmultisig;
    CKey keys[4];
    nonminimalmultisig << std::vector<unsigned char>{2};
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << 4 << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);

    // A 2of4 but using a direct push rather than OP_4
    nonminimalmultisig.clear();
    nonminimalmultisig << 2;
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << std::vector<unsigned char>{4} << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);
}

BOOST_AUTO_TEST_SUITE_END()
