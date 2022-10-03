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
#ifndef __crypto_hpp__
#define __crypto_hpp__

#include <cstddef>

#include <jinx/slice.hpp>

#include <openssl/evp.h>

namespace crypto {
    
void sha256(const void* data, size_t size, unsigned char* output);
bool verify_tls_key(const void* aad, size_t aad_len, void* key, size_t key_len, void* output, size_t md_len);

bool encrypt(
    const EVP_CIPHER* cipher,
    jinx::SliceConst aad, 
    jinx::SliceConst nonce, 
    jinx::SliceConst key, 
    jinx::SliceConst data, 
    jinx::SliceMutable output, 
    jinx::SliceMutable tag);
bool decrypt(
    const EVP_CIPHER* cipher,
    jinx::SliceConst aad, 
    jinx::SliceConst nonce, 
    jinx::SliceConst key, 
    jinx::SliceConst data, 
    jinx::SliceMutable output, 
    jinx::SliceMutable tag);

}

#endif
