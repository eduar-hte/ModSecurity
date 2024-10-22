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

#include "src/actions/maturity.h"

#include <fmt/format.h>

#include "modsecurity/rule_with_actions.h"


namespace modsecurity::actions {


bool Maturity::init(std::string *error) {
    try {
        m_maturity = std::stoi(m_parser_payload);
    }  catch (...) {
        error->assign(fmt::format("Maturity: The input \"{}\" is " \
            "not a number.", m_parser_payload));
        return false;
    }
    return true;
}


bool Maturity::evaluate(RuleWithActions *rule, Transaction *transaction) {
    rule->m_maturity = m_maturity;
    return true;
}


}  // namespace modsecurity::actions
