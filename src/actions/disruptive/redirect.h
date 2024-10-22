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

#ifndef SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_
#define SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_

#include <string>
#include <memory>
#include <utility>

#include "modsecurity/actions/action.h"
#include "modsecurity/rule_message.h"
#include "src/run_time_string.h"

namespace modsecurity::actions::disruptive {


class Redirect : public Action {
 public:
    explicit Redirect(const std::string &action)
        : Action(action),
        m_status(0),
        m_string(nullptr) { }

    explicit Redirect(std::unique_ptr<RunTimeString> z)
        : Action("redirert"),
            m_status(0),
            m_string(std::move(z)) { }

    bool evaluate(RuleWithActions &rule, Transaction *transaction, RuleMessage &ruleMessage) override;
    bool init(std::string *error) override;
    bool isDisruptive() override { return true; }

 private:
    int m_status;
    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace modsecurity::actions::disruptive

#endif  // SRC_ACTIONS_DISRUPTIVE_REDIRECT_H_
