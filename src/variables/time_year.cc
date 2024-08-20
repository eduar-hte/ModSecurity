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

#include "src/variables/time_year.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <utility>

#include "modsecurity/transaction.h"

#ifdef WIN32
#include "src/compat/msvc.h"
#endif

namespace modsecurity {
namespace variables {

void TimeYear::evaluate(Transaction *transaction,
    RuleWithActions *rule,
    std::vector<const VariableValue *> &l) {
    time_t timer;
    time(&timer);

    struct tm timeinfo;
    localtime_r(&timer, &timeinfo);

    char tstr[std::size("yyyy")];
    strftime(tstr, std::size(tstr), "%Y", &timeinfo);

    transaction->m_variableTimeYear.assign(tstr);

    l.push_back(new VariableValue(&m_retName,
        &transaction->m_variableTimeYear));
}


}  // namespace variables
}  // namespace modsecurity
