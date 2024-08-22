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

#ifndef SRC_ACTIONS_INIT_COL_H_
#define SRC_ACTIONS_INIT_COL_H_

#include <string>
#include <utility>
#include <memory>

#include "modsecurity/actions/action.h"
#include "src/run_time_string.h"

namespace modsecurity::actions {


class InitCol : public Action {
 public:
    explicit InitCol(const std::string &action) : Action(action) { }

    InitCol(const std::string &action, std::unique_ptr<RunTimeString> z)
        : Action(action),
            m_string(std::move(z)) { }

    bool evaluate(RuleWithActions &rule, Transaction *transaction) override;
    bool init(std::string *error) override;
 private:
    std::string m_collection_key;
    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace modsecurity::actions

#endif  // SRC_ACTIONS_INIT_COL_H_
