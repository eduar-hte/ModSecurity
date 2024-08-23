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


#ifndef SRC_COLLECTION_BACKEND_IN_MEMORY_PER_PROCESS_H_
#define SRC_COLLECTION_BACKEND_IN_MEMORY_PER_PROCESS_H_

#include <string>
#include <iostream>
#include <unordered_map>
#include <chrono>
#include <list>
#include <vector>
#include <algorithm>
#include <memory>
#include <shared_mutex>

#include "modsecurity/variable_value.h"
#include "modsecurity/collection/collection.h"
#include "src/collection/backend/collection_data.h"
#include "src/variables/variable.h"

namespace modsecurity::collection::backend {

/*
 * FIXME:
 *
 * This was an example grabbed from:
 * http://stackoverflow.com/questions/8627698/case-insensitive-stl-containers-e-g-stdunordered-set
 *
 * We have to have a better hash function, maybe based on the std::hash.
 *
 */
struct MyEqual {
    using is_transparent = void;

    template<typename T, typename U>
    bool operator()(const T& Left, const U& Right) const {
        return Left.size() == Right.size()
             && std::equal(Left.begin(), Left.end(), Right.begin(),
            [](char a, char b) {
            return tolower(a) == tolower(b);
        });
    }
};

struct MyHash{
    using is_transparent = void;

    template<typename T>
    size_t operator()(const T& Keyval) const {
        // You might need a better hash function than this
        size_t h = 0;
        std::for_each(Keyval.begin(), Keyval.end(), [&](char c) {
            h += tolower(c);
        });
        return h;
    }
};

class InMemoryPerProcess :
    public Collection {
 public:
    explicit InMemoryPerProcess(std::string_view name);
    ~InMemoryPerProcess() override;
    void store(std::string_view key, std::string_view value);

    bool storeOrUpdateFirst(std::string_view key,
        std::string_view value) override;

    bool updateFirst(std::string_view key,
        std::string_view value) override;

    void del(std::string_view key) override;

    void delIfExpired(std::string_view key);

    void setExpiry(std::string_view key, int32_t expiry_seconds) override;

    std::unique_ptr<std::string> resolveFirst(std::string_view var) override;

    void resolveSingleMatch(std::string_view var,
        std::vector<const VariableValue *> &l) override;
    void resolveMultiMatches(std::string_view var,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) override;
    void resolveRegularExpression(std::string_view var,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) override;

    /* store */
    void store(std::string_view key, std::string_view compartment,
        std::string_view value) {
        store(nkey(compartment, key), value);
    }

    void store(std::string_view key, std::string_view compartment,
        std::string_view compartment2, std::string_view value) {
        store(nkey(compartment, compartment2, key), value);
    }

 private:
    std::unordered_multimap<std::string, CollectionData,
        /*std::hash<std::string>*/MyHash, MyEqual> m_map;
    std::shared_mutex m_mutex;
};

}  // namespace modsecurity::collection::backend


#endif  // SRC_COLLECTION_BACKEND_IN_MEMORY_PER_PROCESS_H_
