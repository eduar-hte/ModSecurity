/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef HEADERS_MODSECURITY_COLLECTION_UTIL_H_H
#define HEADERS_MODSECURITY_COLLECTION_UTIL_H_H

#ifdef __cplusplus
#include <string>
#include <algorithm>


namespace modsecurity {


struct MyEqual {
#if __cplusplus >= 202002L
    using is_transparent = void;

    template<typename T, typename U>
    bool operator()(const T& Left, const U& Right) const {
#else
    bool operator()(const std::string& Left, const std::string& Right) const {
#endif
        return Left.size() == Right.size()
             && std::equal(Left.begin(), Left.end(), Right.begin(),
            [](char a, char b) {
            return tolower(a) == tolower(b);
        });
    }
};


struct MyHash{
#if __cplusplus >= 202002L
    using is_transparent = void;

    template<typename T>
    std::size_t operator()(const T& Keyval) const {
#else
    std::size_t operator()(const std::string& Keyval) const {
#endif
        // computes the hash using a variant of the
        // Fowler-Noll-Vo hash function (FNV-1a)
        constexpr std::uint64_t prime{0x01000193}; // FNV prime
        std::size_t hash{0x811c9dc5}; // FNV offset basis
        for (char c : Keyval) {
            hash ^= tolower(c);
            hash *= prime; 
        }
        return hash;
    }
};


}  // namespace modsecurity


#endif  // __cplusplus

#endif  // HEADERS_MODSECURITY_COLLECTION_UTIL_H_H
