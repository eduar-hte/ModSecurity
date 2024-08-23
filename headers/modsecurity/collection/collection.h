/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2023 Trustwave Holdings, Inc. (http://www.trustwave.com/)
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


#ifdef __cplusplus
#include <string>
#include <vector>
#include <algorithm>
#include <string_view>
#include <fmt/format.h>
#endif


#include "modsecurity/variable_value.h"


#ifndef HEADERS_MODSECURITY_COLLECTION_COLLECTION_H_
#define HEADERS_MODSECURITY_COLLECTION_COLLECTION_H_

#ifndef __cplusplus
typedef struct Variable_t Variables;
#endif

#ifdef __cplusplus
namespace modsecurity {
namespace variables {
class KeyExclusions;
}
namespace collection {

class Collection {
 public:
    explicit Collection(std::string_view a) : m_name(a) { }
    virtual ~Collection() { }

#if __cplusplus >= 202002L
    using KeyType = std::string_view;
#else
    using KeyType = const std::string&;
#endif

    virtual bool storeOrUpdateFirst(KeyType key,
        std::string_view value) = 0;

    virtual bool updateFirst(KeyType key,
        std::string_view value) = 0;

    virtual void del(KeyType key) = 0;

    virtual void setExpiry(KeyType key, int32_t expiry_seconds) = 0;

    virtual std::unique_ptr<std::string> resolveFirst(
        KeyType key) = 0;

    virtual void resolveSingleMatch(KeyType key,
        std::vector<const VariableValue *> &l) = 0;
    virtual void resolveMultiMatches(KeyType key,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) = 0;
    virtual void resolveRegularExpression(KeyType key,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) = 0;


    /* storeOrUpdateFirst */
    bool storeOrUpdateFirst(KeyType key,
        std::string_view compartment, std::string_view value) {
        return storeOrUpdateFirst(nkey(compartment, key), value);
    }


    bool storeOrUpdateFirst(KeyType key,
        std::string_view compartment, std::string_view compartment2,
        std::string_view value) {
        return storeOrUpdateFirst(nkey(compartment, compartment2, key), value);
    }


    /* updateFirst */
    bool updateFirst(KeyType key, std::string_view compartment,
        std::string_view value) {
        return updateFirst(nkey(compartment, key), value);
    }


    bool updateFirst(KeyType key, std::string_view compartment,
        std::string_view compartment2, std::string_view value) {
        return updateFirst(nkey(compartment, compartment2, key), value);
    }


    /* del */
    void del(KeyType key, std::string_view compartment) {
        del(nkey(compartment, key));
    }


    void del(KeyType key, std::string_view compartment,
        std::string_view compartment2) {
        del(nkey(compartment, compartment2, key));
    }


    /* setExpiry */
    void setExpiry(KeyType key, std::string_view compartment,
        int32_t expiry_seconds) {
        setExpiry(nkey(compartment, key), expiry_seconds);
    }


    void setExpiry(KeyType key, std::string_view compartment,
        std::string_view compartment2, int32_t expiry_seconds) {
        setExpiry(nkey(compartment, compartment2, key), expiry_seconds);
    }


    /* resolveFirst */
    std::unique_ptr<std::string> resolveFirst(KeyType var,
        std::string_view compartment) {
        return resolveFirst(nkey(compartment, var));
    }


    std::unique_ptr<std::string> resolveFirst(KeyType var,
        std::string_view compartment, std::string_view compartment2) {
        return resolveFirst(nkey(compartment, compartment2, var));
    }


    /* resolveSingleMatch */
    void resolveSingleMatch(KeyType var,
        std::string_view compartment, std::vector<const VariableValue *> &l) {
        resolveSingleMatch(nkey(compartment, var), l);
    }


    void resolveSingleMatch(KeyType var,
        std::string_view compartment, std::string_view compartment2,
        std::vector<const VariableValue *> &l) {
        resolveSingleMatch(nkey(compartment, compartment2, var), l);
    }


    /* resolveMultiMatches */
    void resolveMultiMatches(KeyType var,
        std::string_view compartment, std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) {
        resolveMultiMatches(nkey(compartment, var), l, ke);
    }


    void resolveMultiMatches(KeyType var,
        std::string_view compartment, std::string_view compartment2,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) {
        resolveMultiMatches(nkey(compartment, compartment2, var), l, ke);
    }


    /* resolveRegularExpression */
    void resolveRegularExpression(KeyType var,
        std::string_view compartment, std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) {
        resolveRegularExpression(nkey(compartment, var), l, ke);
    }


    void resolveRegularExpression(KeyType var,
        std::string_view compartment, std::string_view compartment2,
        std::vector<const VariableValue *> &l, variables::KeyExclusions &ke) {
        resolveRegularExpression(nkey(compartment, compartment2, var), l, ke);
    }

    std::string m_name;

 protected:

    static inline std::string nkey(std::string_view compartment, std::string_view key) {
        return fmt::format("{}::{}", compartment, key);
    }
    static inline std::string nkey(std::string_view compartment, std::string_view compartment2, std::string_view key) {
        return fmt::format("{}::{}::{}", compartment, compartment2, key);
    }
};

}  // namespace collection
}  // namespace modsecurity
#endif


#endif  // HEADERS_MODSECURITY_COLLECTION_COLLECTION_H_
