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

#include "src/utils/regex.h"

#include <string>
#include <list>

#include <fstream>
#include <iostream>

#include "src/utils/geo_lookup.h"


class Pcre2MatchContextPtr {
 public:
    Pcre2MatchContextPtr()
        : m_match_context(pcre2_match_context_create(NULL)) {}

		Pcre2MatchContextPtr(const Pcre2MatchContextPtr&) = delete;
		Pcre2MatchContextPtr& operator=(const Pcre2MatchContextPtr&) = delete;

    ~Pcre2MatchContextPtr() {
        pcre2_match_context_free(m_match_context);
    }

    operator pcre2_match_context*() const {
        return m_match_context;
    }

 private:
    pcre2_match_context *m_match_context;
};

namespace modsecurity {
namespace Utils {

// Helper function to tell us if the current config indicates CRLF is a valid newline sequence
bool crlfIsNewline() {
    uint32_t newline = 0;
    pcre2_config(PCRE2_CONFIG_NEWLINE, &newline);
    bool crlf_is_newline =
        newline == PCRE2_NEWLINE_ANY ||
        newline == PCRE2_NEWLINE_CRLF ||
        newline == PCRE2_NEWLINE_ANYCRLF;
    return crlf_is_newline;
}

Regex::Regex(const std::string& pattern_, bool ignoreCase)
    : pattern(pattern_.empty() ? ".*" : pattern_) {
    PCRE2_SPTR pcre2_pattern = reinterpret_cast<PCRE2_SPTR>(pattern.c_str());
    uint32_t pcre2_options = (PCRE2_DOTALL|PCRE2_MULTILINE);
    if (ignoreCase) {
        pcre2_options |= PCRE2_CASELESS;
    }
    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    m_pc = pcre2_compile(pcre2_pattern, PCRE2_ZERO_TERMINATED,
        pcre2_options, &errornumber, &erroroffset, NULL);
    m_pcje = pcre2_jit_compile(m_pc, PCRE2_JIT_COMPLETE);
}


Regex::~Regex() {
    pcre2_code_free(m_pc);
}


std::list<SMatch> Regex::searchAll(const std::string& s) const {
    std::list<SMatch> retList;
    int rc = 0;
    PCRE2_SPTR pcre2_s = reinterpret_cast<PCRE2_SPTR>(s.c_str());
    PCRE2_SIZE offset = 0;

    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(m_pc, NULL);
    do {
        if (m_pcje == 0) {
            rc = pcre2_jit_match(m_pc, pcre2_s, s.length(),
                            offset, 0, match_data, NULL);
        } 
        
        if (m_pcje != 0 || rc == PCRE2_ERROR_JIT_STACKLIMIT) {
            rc = pcre2_match(m_pc, pcre2_s, s.length(),
                            offset, PCRE2_NO_JIT, match_data, NULL);
        }
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        for (int i = 0; i < rc; i++) {
            size_t start = ovector[2*i];
            size_t end = ovector[2*i+1];
            size_t len = end - start;
            if (end > s.size()) {
                rc = -1;
                break;
            }
            std::string match = std::string(s, start, len);
            offset = start + len;
            retList.push_front(SMatch(match, start));

            if (len == 0) {
                rc = 0;
                break;
            }
        }
    } while (rc > 0);

    pcre2_match_data_free(match_data);
    return retList;
}

RegexResult Regex::searchOneMatch(const std::string& s, std::vector<SMatchCapture>& captures, unsigned long match_limit) const {
    Pcre2MatchContextPtr match_context;
    if (match_limit > 0) {
        // TODO: What if setting the match limit fails?
        pcre2_set_match_limit(match_context, match_limit);
    }

    PCRE2_SPTR pcre2_s = reinterpret_cast<PCRE2_SPTR>(s.c_str());
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(m_pc, NULL);
    int rc = 0;
    if (m_pcje == 0) {
        rc = pcre2_jit_match(m_pc, pcre2_s, s.length(), 0, 0, match_data, match_context);
    } 
    
    if (m_pcje != 0 || rc == PCRE2_ERROR_JIT_STACKLIMIT) {
        rc = pcre2_match(m_pc, pcre2_s, s.length(), 0, PCRE2_NO_JIT, match_data, match_context);
    }
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

    for (int i = 0; i < rc; i++) {
        size_t start = ovector[2*i];
        size_t end = ovector[2*i+1];
        size_t len = end - start;
        if (end > s.size()) {
            continue;
        }
        SMatchCapture capture(i, start, len);
        captures.push_back(capture);
    }

    pcre2_match_data_free(match_data);
    return to_regex_result(rc);
}

RegexResult Regex::searchGlobal(const std::string& s, std::vector<SMatchCapture>& captures, unsigned long match_limit) const {
    bool prev_match_zero_length = false;
    Pcre2MatchContextPtr match_context;
    if (match_limit > 0) {
        // TODO: What if setting the match limit fails?
        pcre2_set_match_limit(match_context, match_limit);
    }

    PCRE2_SPTR pcre2_s = reinterpret_cast<PCRE2_SPTR>(s.c_str());
    PCRE2_SIZE startOffset = 0;

    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(m_pc, NULL);
    while (startOffset <= s.length()) {
        uint32_t pcre2_options = 0;
        if (prev_match_zero_length) {
            pcre2_options = PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED;
        }
        int rc = pcre2_match(m_pc, pcre2_s, s.length(),
                            startOffset, pcre2_options, match_data, match_context);
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

        if (rc > 0) {
            size_t firstGroupForThisFullMatch = captures.size();
            for (int i = 0; i < rc; i++) {
                size_t start = ovector[2*i];
                size_t end = ovector[2*i+1];
                size_t len = end - start;
                if (end > s.length()) {
                    continue;
                }
                SMatchCapture capture(firstGroupForThisFullMatch + i, start, len);
                captures.push_back(capture);

                if (i == 0) {
                    if (len > 0) {
                        // normal case; next call to pcre_exec should start after the end of the last full match string
                        startOffset = end;
                        prev_match_zero_length = false;
                    } else {
                        if ( startOffset == s.length()) {
                            // zero-length match at end of string; force end of while-loop
                            startOffset++;
                        } else {
                            // zero-length match mid-string; adjust next match attempt
                            prev_match_zero_length = true;
                        }
                    }
                }
            }
        } else {
            if (prev_match_zero_length) {
                // The n-1 search found a zero-length match, so we did a subsequent search
                // with the special flags. That subsequent exec did not find a match, so now advance
                // by one character (unless CRLF, then advance by two)
                startOffset++;
                if (crlfIsNewline() && (startOffset < s.length()) && (s[startOffset-1] == '\r')
                    && (s[startOffset] == '\n')) {
                    startOffset++;
                }
                prev_match_zero_length = false;
            } else {
                // normal case; no match on most recent scan (with options=0).  We are done.
                break;
            }
        }
    }

    pcre2_match_data_free(match_data);
    return RegexResult::Ok;
}

int Regex::search(const std::string& s, SMatch *match) const {
    PCRE2_SPTR pcre2_s = reinterpret_cast<PCRE2_SPTR>(s.c_str());
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(m_pc, NULL);
    int ret = 0;
    if (m_pcje == 0) {
        ret = pcre2_match(m_pc, pcre2_s, s.length(),
            0, 0, match_data, NULL) > 0;
    } 
    
    if (m_pcje != 0 || ret == PCRE2_ERROR_JIT_STACKLIMIT) {
        ret = pcre2_match(m_pc, pcre2_s, s.length(),
            0, PCRE2_NO_JIT, match_data, NULL) > 0;
    }
    if (ret > 0) { // match
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        *match = SMatch(
            std::string(s, ovector[ret-1], ovector[ret] - ovector[ret-1]),
            0);
    }

    pcre2_match_data_free(match_data);
    return ret;
}

int Regex::search(const std::string& s) const {
    PCRE2_SPTR pcre2_s = reinterpret_cast<PCRE2_SPTR>(s.c_str());
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(m_pc, NULL);
    int rc = 0;
    if (m_pcje == 0) {
        rc = pcre2_jit_match(m_pc, pcre2_s, s.length(), 0, 0, match_data, NULL);
    }

    if (m_pcje != 0 || rc == PCRE2_ERROR_JIT_STACKLIMIT) {
        rc = pcre2_match(m_pc, pcre2_s, s.length(), 0, PCRE2_NO_JIT, match_data, NULL);
    }
    pcre2_match_data_free(match_data);
    if (rc > 0) {
        return 1; // match
    } else {
        return 0; // no match
    }
}

RegexResult Regex::to_regex_result(int pcre_exec_result) const {
    if (
        pcre_exec_result > 0 ||
        pcre_exec_result == PCRE2_ERROR_NOMATCH
    ) {
        return RegexResult::Ok;
    } else if(
        pcre_exec_result == PCRE2_ERROR_MATCHLIMIT
    ) {
        return RegexResult::ErrorMatchLimit;
    } else {
        // Note that this can include the case where the PCRE result was zero.
        // Zero is returned if the offset vector is not large enough and can be considered an error.
        return RegexResult::ErrorOther;
    }
}

}  // namespace Utils
}  // namespace modsecurity
