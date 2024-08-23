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

#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "modsecurity/anchored_set_variable.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "src/utils/regex.h"
#include "src/variables/variable.h"

namespace modsecurity {


AnchoredSetVariable::AnchoredSetVariable(Transaction *t,
    const std::string &name)
    : m_transaction(t),
    m_name(name) {
        reserve(10);
    }


AnchoredSetVariable::~AnchoredSetVariable() {
    unset();
}


void AnchoredSetVariable::unset() {
    for (const auto& x : *this) {
        VariableValue *var = x.second;
        delete var;
    }
    clear();
}


void AnchoredSetVariable::set(KeyType key,
    std::string_view value, size_t offset, size_t len) {
    auto var = new VariableValue(m_name, key, value);
    var->addOrigin(len, offset);
    emplace(key, var);
}


void AnchoredSetVariable::set(KeyType key,
    std::string_view value, size_t offset) {
    auto var = new VariableValue(m_name, key, value);
    var->addOrigin(value.size(), offset);
    emplace(key, var);
}


void AnchoredSetVariable::resolve(
    std::vector<const VariableValue *> &l) {
    for (const auto& [key, var] : *this) {
        l.insert(l.begin(), new VariableValue(*var));
    }
}


void AnchoredSetVariable::resolve(
    std::vector<const VariableValue *> &l,
    variables::KeyExclusions &ke) {
    for (const auto& [key, var] : *this) {
        if (!ke.toOmit(key)) {
            l.insert(l.begin(), new VariableValue(*var));
        } else {
            ms_dbg_a(m_transaction, 7, "Excluding key: " + key
                + " from target value.");
        }
    }
}


void AnchoredSetVariable::resolve(KeyType key,
    std::vector<const VariableValue *> &l) {

    auto range = this->equal_range(key);
    for (auto it = range.first; it != range.second; ++it) {
        l.push_back(new VariableValue(*it->second));
    }
}


std::unique_ptr<std::string> AnchoredSetVariable::resolveFirst(
    KeyType key) {

    if (auto search = this->find(key); search != this->end()) {
        return std::make_unique<std::string>(search->second->getValue());
    }

    return nullptr;
}


void AnchoredSetVariable::resolveRegularExpression(Utils::Regex *r,
    std::vector<const VariableValue *> &l) {
    for (const auto& [key, var] : *this) {
        int ret = Utils::regex_search(key, *r);
        if (ret <= 0) {
            continue;
        }
        l.insert(l.begin(), new VariableValue(*var));
    }
}


void AnchoredSetVariable::resolveRegularExpression(Utils::Regex *r,
    std::vector<const VariableValue *> &l,
    variables::KeyExclusions &ke) {
    for (const auto& [key, var] : *this) {
        int ret = Utils::regex_search(key, *r);
        if (ret <= 0) {
            continue;
        }
        if (!ke.toOmit(key)) {
            l.insert(l.begin(), new VariableValue(*var));
        } else {
            ms_dbg_a(m_transaction, 7, "Excluding key: " + key
                + " from target value.");
        }
    }
}


}  // namespace modsecurity
