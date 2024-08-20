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


#ifdef __cplusplus
#include <string>
#include <algorithm>
#include <memory>
#include <functional>
#include <cassert>
#endif

#include "modsecurity/variable_value.h"
#include "modsecurity/anchored_set_variable.h"


#ifndef HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_TRANSLATION_PROXY_H_
#define HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_TRANSLATION_PROXY_H_

#ifdef __cplusplus

namespace modsecurity {


class AnchoredSetVariableTranslationProxy {
 public:
    AnchoredSetVariableTranslationProxy(
        const std::string &name,
        AnchoredSetVariable *fount)
        : m_name(name),
        m_fount(fount)
    { }

    virtual ~AnchoredSetVariableTranslationProxy() = default;

    void resolve(std::vector<const VariableValue *> &l) {
        m_fount->resolve(l);
        translate(l);
    }

    void resolve(std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) {
        m_fount->resolve(l, ke);
        translate(l);
    }

    void resolve(const std::string &key,
        std::vector<const VariableValue *> &l) {
        m_fount->resolve(key, l);
        translate(l);
    };

    void resolveRegularExpression(Utils::Regex *r,
        std::vector<const VariableValue *> &l) {
        m_fount->resolveRegularExpression(r, l);
        translate(l);
    };

    void resolveRegularExpression(Utils::Regex *r,
        std::vector<const VariableValue *> &l,
        variables::KeyExclusions &ke) {
        m_fount->resolveRegularExpression(r, l, ke);
        translate(l);
    };

    std::unique_ptr<std::string> resolveFirst(const std::string &key) {
        std::vector<const VariableValue *> l;
        resolve(l);

        if (l.empty()) {
            return nullptr;
        }

        auto ret = std::make_unique<std::string>(l[0]->getValue());

        for(auto a : l) {
            delete a;
        }

        return ret;
    }

    std::string m_name;
 private:
    AnchoredSetVariable *m_fount;

    void translate(std::vector<const VariableValue *> &l) const {
        for (auto &v : l) {
            assert(v != nullptr);
            std::unique_ptr<const VariableValue> oldVariableValue(v);
            auto newVariableValue = new VariableValue(m_name, v->getKey(), v->getKey());
            newVariableValue->reserveOrigin(v->getOrigin().size());
            for (const auto &oldOrigin : v->getOrigin()) {
                newVariableValue->addOrigin(
                    v->getKey().size(),
                    oldOrigin.m_offset - v->getKey().size() - 1
                );
            }
            v = newVariableValue;
        }
    };
};

}  // namespace modsecurity

#endif


#endif  // HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_TRANSLATION_PROXY_H_
