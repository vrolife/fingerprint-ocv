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
#include <filesystem>
#include <fstream>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <opencv2/imgproc.hpp>

#include "jinx/logging.hpp"

#include "fingerprint.hpp"
#include "crypto.hpp"

namespace fpc {
using namespace std::string_literals;

bool Fingerprint::merge(const cv::Mat& img)
{
    if (_fingerprint.empty()) {
        _fingerprint = img;
        _mask.create(_fingerprint.size(), CV_32F);
        _mask.setTo(1.0F);
        return true;
    }
    cv::Mat output{};
    cv::Mat mask{};
    auto ret = cvext::merge(_fingerprint, _mask, img, output, mask);
    if (not ret) {
        return false;
    }
    _fingerprint = std::move(output);
    _mask = std::move(mask);
    return true;
}

bool Fingerprint::match(const cv::Mat &img, float min_score, bool filter) const
{
    return cvext::match(_fingerprint, _mask, img, 4, min_score, filter);
}

size_t Fingerprint::total() const
{
    auto sum = cv::sum(_mask);
    return static_cast<size_t>(sum[0]);
}

void Fingerprint::write(cv::FileStorage& fstorage, int idx) const
{
    std::string name{};
    
    name = "user"s + std::to_string(idx);
    fstorage << name << _user;

    name = "name"s + std::to_string(idx);
    fstorage << name << _name;

    name = "print"s + std::to_string(idx);
    fstorage << name << _fingerprint;

    name = "mask"s + std::to_string(idx);
    fstorage << name << _mask;
}

void Fingerprint::read(cv::FileStorage& fstorage, int idx)
{
    std::string name{};

    name = "user"s + std::to_string(idx);
    _user = fstorage[name].string();

    name = "name"s + std::to_string(idx);
    _name = fstorage[name].string();

    name = "print"s + std::to_string(idx);
    _fingerprint = fstorage[name].mat();

    name = "mask"s + std::to_string(idx);
    _mask = fstorage[name].mat();
}
    
void FingerprintStorage::load()
{
    _fingerprints.clear();

    std::filesystem::path filename{_filename};

    if (not std::filesystem::exists(filename)) {
        return;
    }

    size_t filesize = std::filesystem::file_size(filename);

    if (filesize <= 16) {
        return;
    }

    std::vector<unsigned char> encrypted{};
    encrypted.resize(filesize);

    std::vector<unsigned char> data{};
    data.resize(filesize - 16);

    FILE* file = fopen(_filename.c_str(), "rb");
    if (file == nullptr) {
        return;
    }
    fread(encrypted.data(), encrypted.size(), 1, file);
    fclose(file);

    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{_key.data(), 12};

    auto ret = crypto::decrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {encrypted.data(), encrypted.size() - 16}, 
        {data.data(), data.size()}, 
        {encrypted.data() + encrypted.size() - 16, 16});

    if (not ret) {
        return;
    }

    std::string data_string{reinterpret_cast<char*>(data.data()), data.size()};
    cv::FileStorage fstorage{data_string, cv::FileStorage::READ | cv::FileStorage::MEMORY | cv::FileStorage::FORMAT_JSON};

    auto count = (int)fstorage["count"];

    for (int idx = 0 ; idx < count; ++idx) {
        Fingerprint print{};
        print.read(fstorage, idx);
        insert_or_update(std::move(print));
    }
}

void FingerprintStorage::save()
{
    cv::FileStorage fstorage{"memory", cv::FileStorage::WRITE | cv::FileStorage::MEMORY | cv::FileStorage::FORMAT_JSON};
    int count = 0;
    std::string name{};
    for (auto& user : _fingerprints) {
        for (auto& print : user.second) {
            print.second.write(fstorage, count);
            ++ count;
        }
    }
    fstorage.write("count", count);

    auto data = fstorage.releaseAndGetString();

    std::vector<unsigned char> encrypted{};
    encrypted.resize(data.size() + 16);

    jinx::SliceConst key{_key.data(), _key.size()};
    jinx::SliceConst nonce{_key.data(), 12};

    crypto::encrypt(
        EVP_chacha20_poly1305(), 
        key, 
        nonce, 
        key, 
        {data.data(), 
        data.size()}, 
        {encrypted.data(), data.size()},
        {encrypted.data() + data.size(), 16});

    FILE* file = fopen(_filename.c_str(), "wb");
    if (file == nullptr) {
        jinx_log_error() << "write " << _filename << " failed: " << strerror(errno);
    }
    fwrite(encrypted.data(), encrypted.size(), 1, file);
    fclose(file);
}

void FingerprintStorage::init(const std::string &filename, const std::vector<unsigned char>& key)
{
    assert(key.size() == 32);
    _filename = filename;
    _key = key;
    load();
}

void FingerprintStorage::insert_or_update(Fingerprint&& fingerprint)
{
    std::string name = fingerprint._name;
    auto user = _fingerprints.find(fingerprint._user);
    if (user == _fingerprints.end()) {
        auto pair = _fingerprints.emplace(fingerprint._user, std::unordered_map<std::string, Fingerprint>{});
        pair.first->second.emplace(name, std::move(fingerprint));
        return;
    }
    auto print = user->second.find(name);
    if (print == user->second.end()) {
        user->second.emplace(name, std::move(fingerprint));
    } else {
        print->second = std::move(fingerprint);
    }
}

}
