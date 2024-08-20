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

#include "src/variables/env.h"

#include <string_view>

#ifdef WIN32
#include "src/compat/msvc.h"
#endif

#include "modsecurity/transaction.h"

#ifndef WIN32
extern char **environ;
#endif

namespace modsecurity::variables {

void Env::evaluate(Transaction *transaction,
    RuleWithActions *rule,
    std::vector<const VariableValue *> &l) {
    std::map<std::string_view, std::string_view> variableEnvs;
    for (char **current = environ; *current; current++) {
        const auto env = std::string_view{*current};
        const auto pos = env.find_first_of("=");
        if (pos == std::string::npos) {
            continue;
        }
        const auto key = env.substr(0, pos);
        const auto value = env.substr(pos + 1);
        variableEnvs.emplace(key, value);
    }

    const auto hasName = m_name.length() > 0;
    for (const auto& [name, value] : variableEnvs) {
#ifndef WIN32
        if (hasName && name != m_name) {
#else
        if (hasName &&
            (name.length() != m_name.length() ||
            strncasecmp(name.data(), m_name.c_str(), name.length()) != 0)) {
#endif
            continue;
        }
        // (Windows) we need to keep the case from the rule in case that from
        // the environment differs.
        const auto key = hasName ? std::string_view{m_name} : name;
        if (!m_keyExclusion.toOmit(key)) {
            l.push_back(new VariableValue(m_collectionName, key,
                value));
        }
    }
}


}  // namespace modsecurity::variables
