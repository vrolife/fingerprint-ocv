/*
Copyright (C) 2022  pom@vro.life

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef __fingerprint_hpp__
#define __fingerprint_hpp__

#include <string>
#include <vector>
#include <unordered_map>

#include "cvext.hpp"

namespace fpc {

struct Fingerprint
{
    std::string _user{};
    std::string _name{};
    cv::Mat _fingerprint{};
    cv::Mat _mask{};

    Fingerprint() = default;
    Fingerprint(Fingerprint&&) = default;
    Fingerprint(const Fingerprint&) = default;
    ~Fingerprint() = default;

    Fingerprint& operator =(Fingerprint&&) = default;
    Fingerprint& operator =(const Fingerprint&) = default;

    bool merge(const cv::Mat& img);
    bool match(const cv::Mat& img, float min_score, bool filter) const;

    size_t total() const;

    void write(cv::FileStorage& fstorage, int idx) const;
    void read(cv::FileStorage& fstorage, int idx);

    static bool is_any(const std::string& name) {
        return name.empty() or name == "any";
    }
};

class FingerprintStorage
{
    std::string _filename{};
    std::vector<unsigned char> _key{};
    std::unordered_map<std::string, std::unordered_map<std::string, Fingerprint>> _fingerprints{};

public:
    template<typename F>
    void foreach(const std::string& username, F&& fun) {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return;
        }

        for (auto& pair : user->second) {
            auto ret = fun(pair.second);
            if (ret) {
                return;
            }
        }
    }

    size_t get_enrolled_count(const std::string& username) {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return 0;
        }
        return user->second.size();
    }

    void delete_all(const std::string& username)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return;
        }
        user->second.clear();
    }

    bool delete_fingerprint(const std::string& username, const std::string& name)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return false;
        }

        auto print = user->second.find(name);
        if (print != user->second.end()) {
            user->second.erase(print);
            return true;
        }

        return false;
    }

    bool check(const std::string& username, const std::string& name)
    {
        auto user = _fingerprints.find(username);
        if (user == _fingerprints.end()) {
            return false;
        }

        auto print = user->second.find(name);
        return print != user->second.end();
    }

    void insert_or_update(Fingerprint&& fingerprint);
    
    void load();
    void save();

    void reset() {
        _filename.clear();
        _key.clear();
        _fingerprints.clear();
    }

    void init(const std::string& filename, const std::vector<unsigned char>& key);
};

}

#endif
