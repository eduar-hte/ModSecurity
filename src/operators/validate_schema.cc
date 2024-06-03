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

#include "src/operators/validate_schema.h"

#include <string>
#include <fmt/format.h>

#include "src/operators/operator.h"
#include "src/request_body_processor/xml.h"
#include "src/utils/system.h"


namespace modsecurity {
namespace operators {

#ifdef WITH_LIBXML2

bool ValidateSchema::init(const std::string &file, std::string *error) {
    std::string err;
    m_resource = utils::find_resource(m_param, file, &err);
    if (m_resource == "") {
        error->assign(fmt::format("XML: File not found: {}. {}", m_param, err));
        return false;
    }

    return true;
}


bool ValidateSchema::evaluate(Transaction *transaction,
    const std::string &str) {

    if (transaction->m_xml->m_data.doc == NULL) {
        ms_dbg_a(transaction, 4, "XML document tree could not be found for " \
            "schema validation.");
        return true;
    }

    if (transaction->m_xml->m_data.well_formed != 1) {
        ms_dbg_a(transaction, 4, "XML: Schema validation failed because " \
            "content is not well formed.");
        return true;
    }

    xmlSchemaParserCtxtPtr parserCtx = xmlSchemaNewParserCtxt(m_resource.c_str());
    if (parserCtx == NULL) {
        const auto err = fmt::format("XML: Failed to load Schema from file: {}. {}",
            m_resource, !m_err.empty() ? m_err : "");
        ms_dbg_a(transaction, 4, err);
        return true;
    }

    xmlSchemaSetParserErrors(parserCtx,
        (xmlSchemaValidityErrorFunc)error_load,
        (xmlSchemaValidityWarningFunc)warn_load, &m_err);

    xmlThrDefSetGenericErrorFunc(parserCtx,
        null_error);

    xmlSetGenericErrorFunc(parserCtx,
        null_error);

    xmlSchemaPtr schema = xmlSchemaParse(parserCtx);
    if (schema == NULL) {
        const auto err = fmt::format("XML: Failed to load Schema: {}. {}",
            m_resource, !m_err.empty() ? m_err : "");
        ms_dbg_a(transaction, 4, err);
        xmlSchemaFreeParserCtxt(parserCtx);
        return true;
    }

    xmlSchemaValidCtxtPtr validCtx = xmlSchemaNewValidCtxt(schema);
    if (validCtx == NULL) {
        const auto err = fmt::format("XML: Failed to create validation context. {}",
            !m_err.empty() ? m_err : "");
        ms_dbg_a(transaction, 4, err);
        xmlSchemaFree(schema);
        xmlSchemaFreeParserCtxt(parserCtx);
        return true;
    }

    /* Send validator errors/warnings to msr_log */
    xmlSchemaSetValidErrors(validCtx,
        (xmlSchemaValidityErrorFunc)error_runtime,
        (xmlSchemaValidityWarningFunc)warn_runtime, transaction);

    int rc = xmlSchemaValidateDoc(validCtx, transaction->m_xml->m_data.doc);

    xmlSchemaFreeValidCtxt(validCtx);
    xmlSchemaFree(schema);
    xmlSchemaFreeParserCtxt(parserCtx);
    if (rc != 0) {
        ms_dbg_a(transaction, 4, "XML: Schema validation failed.");
        return true; /* No match. */
    } else {
        ms_dbg_a(transaction, 4, fmt::format("XML: Successfully validated payload against " \
            "Schema: {}", m_resource));
        return false;
    }
}

#endif

}  // namespace operators
}  // namespace modsecurity
