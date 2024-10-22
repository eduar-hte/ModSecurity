/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2022 Trustwave Holdings, Inc. (http://www.trustwave.com/)
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

#ifndef SRC_ACTIONS_CTL_AUDIT_ENGINE_H_
#define SRC_ACTIONS_CTL_AUDIT_ENGINE_H_

#include <string>

#include "modsecurity/rules_set_properties.h"
#include "modsecurity/actions/action.h"

#include "modsecurity/audit_log.h"

namespace modsecurity::actions::ctl {


class AuditEngine : public Action {
 public:
    explicit AuditEngine(const std::string &action)
        : Action(action),
        m_auditEngine(audit_log::AuditLog::AuditLogStatus::NotSetLogStatus) { }

    bool init(std::string *error) override;
    bool evaluate(RuleWithActions &rule, Transaction *transaction) override;

    audit_log::AuditLog::AuditLogStatus m_auditEngine;
};


}  // namespace modsecurity::actions::ctl

#endif  // SRC_ACTIONS_CTL_AUDIT_ENGINE_H_
