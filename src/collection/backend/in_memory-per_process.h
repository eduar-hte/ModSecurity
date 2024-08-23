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
#include "modsecurity/collection/util.h"
#include "src/collection/backend/collection_data.h"
#include "src/variables/variable.h"

namespace modsecurity::collection::backend {


class InMemoryPerProcess :
    public Collection {
 public:
    explicit InMemoryPerProcess(std::string_view name);
    ~InMemoryPerProcess() override;
    void store(KeyType key, std::string_view value);

    bool storeOrUpdateFirst(KeyType key,
        std::string_view value) override;

    bool updateFirst(KeyType key,
        std::string_view value) override;

    void del(KeyType key) override;

    void delIfExpired(KeyType key);

    void setExpiry(KeyType key, int32_t expiry_seconds) override;

    std::unique_ptr<std::string> resolveFirst(KeyType var) override;

    void resolveSingleMatch(KeyType var,
        std::vector<const VariableValue *> &l) override;
    void resolveMultiMatches(KeyType var,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) override;
    void resolveRegularExpression(KeyType var,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) override;

    /* store */
    void store(KeyType key, std::string_view compartment,
        std::string_view value) {
        store(nkey(compartment, key), value);
    }

    void store(KeyType key, std::string_view compartment,
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
