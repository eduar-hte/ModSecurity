/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2023 Trustwave Holdings, Inc. (http://www.trustwave.com/)
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

#include "modsecurity/rule_message.h"

#include <fmt/format.h>

#include "modsecurity/rules_set.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "src/utils/string.h"

namespace modsecurity {


std::string RuleMessage::_details(const RuleMessage &rm) {
    auto msg = fmt::format(R"( [file "{}"] [line "{}"] [id "{}"] [rev "{}"] [msg "{}"])" \
        R"( [data "{}"] [severity "{}"] [ver "{}"] [maturity "{}"] [accuracy "{}"])",
        rm.m_rule.getFileName(),
        rm.m_rule.getLineNumber(),
        rm.m_rule.m_ruleId,
        utils::string::toHexIfNeeded(rm.m_rule.m_rev, true),
        rm.m_message,
        utils::string::toHexIfNeeded(utils::string::limitTo(200, rm.m_data), true),
        rm.m_severity,
        utils::string::toHexIfNeeded(rm.m_rule.m_ver, true),
        rm.m_rule.m_maturity,
        rm.m_rule.m_accuracy);

    for (const auto &a : rm.m_tags) {
        msg.append(fmt::format(R"( [tag "{}"])", utils::string::toHexIfNeeded(a, true)));
    }

    msg.append(fmt::format(R"( [hostname "{}"] [uri "{}"] [unique_id "{}"] [ref "{}"])",
        rm.m_transaction.m_requestHostName,
        utils::string::limitTo(200, rm.m_transaction.m_uri_no_query_string_decoded),
        rm.m_transaction.m_id,
        utils::string::limitTo(200, rm.m_reference)));

    return msg;
}


std::string RuleMessage::_errorLogTail(const RuleMessage &rm) {
    return fmt::format(R"([hostname "{}"] [uri "{}"] [unique_id "{}"])",
        rm.m_transaction.m_serverIpAddress,
        utils::string::limitTo(200, rm.m_transaction.m_uri_no_query_string_decoded),
        rm.m_transaction.m_id);
}


std::string RuleMessage::log(const RuleMessage &rm, int props, int code) {
    std::string msg("");
    msg.reserve(2048);

    if (props & ClientLogMessageInfo) {
        msg.append(fmt::format(R"([client {}])", rm.m_transaction.m_clientIpAddress));
    }

    if (rm.m_isDisruptive) {
        msg.append(
            (code == -1) ?
                fmt::format("ModSecurity: Access denied with code %d (phase {})",
                    rm.getPhase()) :
                fmt::format("ModSecurity: Access denied with code {} (phase {})",
                    code, rm.getPhase()));
    } else {
        msg.append("ModSecurity: Warning. ");
    }

    msg.append(fmt::format("{}{}", rm.m_match, _details(rm)));

    if (props & ErrorLogTailLogMessageInfo) {
        msg.append(fmt::format(" {}", _errorLogTail(rm)));
    }

    return modsecurity::utils::string::toHexIfNeeded(msg);
}


}  // namespace modsecurity
