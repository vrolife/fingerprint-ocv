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
#ifndef __fpcbio_hpp__
#define __fpcbio_hpp__

#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <system_error>

#include <jinx/openssl/openssl.hpp>
#include <jinx/queue2.hpp>
#include <jinx/buffer.hpp>
#include <jinx/usb/usb.hpp>
#include <jinx/posix.hpp>
#include <jinx/openssl/bio.hpp>

#include <openssl/bio.h>

#define TLS_MAX_FRAGMENT_SIZE 4096

namespace fpcbio {
using namespace jinx::openssl;

struct FPCBufferConfig
{
    constexpr static char const* Name = "FPCBufferConfig";
    static constexpr const size_t Size = TLS_MAX_FRAGMENT_SIZE;
    static constexpr const size_t Reserve = 10;
    static constexpr const long Limit = -1;
    
    struct Information { };
};

typedef jinx::buffer::BufferAllocator<jinx::posix::MemoryProvider, FPCBufferConfig> FPCAllocator;
typedef typename FPCAllocator::BufferType FPCBuffer;

struct BIOPipe
{
    StreamBIO _bio_server{};
    StreamOpenSSL<AsyncIOBIO> _ssl_server{};

    std::vector<unsigned char> _tls_key{};

    jinx::posix::MemoryProvider _memory{};

    FPCAllocator _allocator{_memory};

    BIOPipe();

    void set_tls_key(const std::vector<unsigned char>& tls_key) {
        _tls_key = tls_key;
    }

    BIOPipe* get() { return this; }

    static unsigned int psk_server_cb(SSL* ssl, const char* identity, unsigned char *psk, unsigned int max_psk_len)
    {
        auto* self = reinterpret_cast<BIOPipe*>(SSL_get_app_data(ssl));

        assert(max_psk_len >= self->_tls_key.size());
        // TODO madvise(tls_key, MADV_DONTDUMP | MADV_DONTFORK)
        memcpy(psk, self->_tls_key.data(), self->_tls_key.size());
        return self->_tls_key.size();
    }
};

}

#endif
