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

#ifndef SRC_ACTIONS_CTL_REQUEST_BODY_PROCESSOR_XML_H_
#define SRC_ACTIONS_CTL_REQUEST_BODY_PROCESSOR_XML_H_

#include <string>

#include "modsecurity/actions/action.h"
#include "modsecurity/transaction.h"

namespace modsecurity::actions::ctl {


class RequestBodyProcessorXML : public Action {
 public:
    explicit RequestBodyProcessorXML(const std::string &action) 
        : Action(action) { }

    bool evaluate(RuleWithActions &rule, Transaction *transaction) override;
};


}  // namespace modsecurity::actions::ctl

#endif  // SRC_ACTIONS_CTL_REQUEST_BODY_PROCESSOR_XML_H_
