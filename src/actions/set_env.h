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

#ifndef SRC_ACTIONS_SET_ENV_H_
#define SRC_ACTIONS_SET_ENV_H_

#include <string>
#include <utility>
#include <memory>

#include "modsecurity/actions/action.h"
#include "src/run_time_string.h"

namespace modsecurity::actions {


class SetENV : public Action {
 public:
    explicit SetENV(const std::string &_action)
        : Action(_action) { }

    explicit SetENV(std::unique_ptr<RunTimeString> z)
        : Action("setenv"),
            m_string(std::move(z)) { }

    bool evaluate(RuleWithActions &rule, Transaction *transaction) override;

 private:
    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace modsecurity::actions

#endif  // SRC_ACTIONS_SET_ENV_H_
