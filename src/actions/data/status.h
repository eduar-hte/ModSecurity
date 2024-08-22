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

#ifndef SRC_ACTIONS_DATA_STATUS_H_
#define SRC_ACTIONS_DATA_STATUS_H_

#include <string>
#include <memory>

#include "modsecurity/actions/action.h"
#include "modsecurity/rule_message.h"

namespace modsecurity::actions::data {


class Status : public Action {
 public:
    explicit Status(const std::string &action)
        : Action(action), m_status(0) { }

    bool init(std::string *error) override;
    bool evaluate(RuleWithActions &rule, Transaction *transaction, RuleMessage &ruleMessage) override;

    int m_status;
};


}  // namespace modsecurity::actions::data

#endif  // SRC_ACTIONS_DATA_STATUS_H_
