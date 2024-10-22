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

#include "test/unit/unit_test.h"

#include <string.h>

#include <sstream>
#include <string>
#include <iostream>
#include <iterator>

#include "test/common/colors.h"
#include "src/utils/regex.h"
#include "src/utils/string.h"


namespace modsecurity_test {


static inline void replaceAll(std::string &s, const std::string &search,
    const char replace) {
    for (size_t pos = 0; ; pos += 0) {
        pos = s.find(search, pos);
        if (pos == std::string::npos) {
            break;
        }
        s.erase(pos, search.length());
        s.insert(pos, &replace, 1);
    }
}

static inline void jsonReplace(std::string &str, const modsecurity::Utils::Regex &re, const char *fmt) {
    modsecurity::Utils::SMatch match;

    while (modsecurity::Utils::regex_search(str, match, re)) {
        const auto search = std::string(match.str());
        auto toBeReplaced = search;
        toBeReplaced.erase(0, 2);
        unsigned int p;
        sscanf(toBeReplaced.c_str(), fmt, &p);
        replaceAll(str, search, p);
    }
}

void json2bin(std::string &str) {
    modsecurity::Utils::Regex re("\\\\x([a-z0-9A-Z]{2})");
    jsonReplace(str, re, "%3x");

    modsecurity::Utils::Regex re2("\\\\u([a-z0-9A-Z]{4})");
    jsonReplace(str, re2, "%4x");
}


std::string UnitTest::print() const {
    std::stringstream i;

    i << KRED << "Test failed." << RESET;
    i << " From: " << this->filename << std::endl;
    i << "{" << std::endl;
    i << "  \"ret\": \"" << this->ret << "\"" << std::endl;
    i << "  \"type\": \"" << this->type << "\"" << std::endl;
    i << "  \"name\": \"" << this->name << "\"" << std::endl;
    i << "  \"input\": \"" << this->input << "\"" << std::endl;
    i << "  \"param\": \"" << this->param << "\"" << std::endl;
    i << "  \"output\": \"" << this->output << "\"" << std::endl;
    i << "}" << std::endl;
    if (this->ret != this->result.ret) {
        i << "Expecting: \"" << this->ret << "\" - returned: \"";
        i << this->result.ret << "\"" << std::endl;
    }
    if (this->output != this->result.output) {
        i << "Expecting: \"";
        i << modsecurity::utils::string::toHexIfNeeded(this->output);
        i << "\" - returned: \"";
        i << modsecurity::utils::string::toHexIfNeeded(this->result.output);
        i << "\"";
        i << std::endl;
    }

    return i.str();
}


UnitTest *UnitTest::from_yajl_node(const yajl_val &node) {
    size_t num_tests = node->u.object.len;
    UnitTest *u = new UnitTest();

    for (int i = 0; i < num_tests; i++) {
        const char *key = node->u.object.keys[ i ];
        yajl_val val = node->u.object.values[ i ];

        u->skipped = false;
        if (strcmp(key, "param") == 0) {
           u->param = YAJL_GET_STRING(val);
        } else if (strcmp(key, "input") == 0) {
           u->input = YAJL_GET_STRING(val);
           json2bin(u->input);
        } else if (strcmp(key, "resource") == 0) {
           u->resource = YAJL_GET_STRING(val);
        } else if (strcmp(key, "name") == 0) {
           u->name = YAJL_GET_STRING(val);
        } else if (strcmp(key, "type") == 0) {
           u->type = YAJL_GET_STRING(val);
        } else if (strcmp(key, "ret") == 0) {
           u->ret = YAJL_GET_INTEGER(val);
        } else if (strcmp(key, "output") == 0) {
           u->output = std::string(YAJL_GET_STRING(val));
           json2bin(u->output);
           /*
            * Converting \\u0000 to \0 due to the following gcc bug:
            * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53690
            *
            */
        }
    }

    return u;
}

}  // namespace modsecurity_test
