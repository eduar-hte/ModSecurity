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

#ifndef SRC_ACTIONS_RULE_ID_H_
#define SRC_ACTIONS_RULE_ID_H_

#include <string>

#include "modsecurity/actions/action.h"

namespace modsecurity::actions {


class RuleId : public Action {
 public:
    explicit RuleId(const std::string &action) 
        : Action(action, Kind::ConfigurationKind),
        m_ruleId(0) { }

    bool init(std::string *error) override;
    bool evaluate(RuleWithActions &rule, Transaction *transaction) override;

 private:
    double m_ruleId;
};


}  // namespace modsecurity::actions

#endif  // SRC_ACTIONS_RULE_ID_H_
