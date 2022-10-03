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
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "jinx/openssl/openssl.hpp"

#include "fpcbio.hpp"

namespace fpcbio {

using namespace jinx;
using namespace jinx::openssl;

static int _bio_type = 0;
static BIO_METHOD* _bio_method = nullptr;

BIOPipe::BIOPipe()
{
    _bio_server.initialize().abort_on(Failed_, "faield to create BIO");

    OpenSSLContext context_server{SSL_CTX_new(TLS_server_method())};    
    SSL_CTX_set_options(context_server, SSL_OP_NO_COMPRESSION);
    SSL_CTX_use_psk_identity_hint(context_server, nullptr);
    SSL_CTX_set_psk_server_callback(context_server, psk_server_cb);

    OpenSSLConnection connection_server{SSL_new(context_server)};
    _bio_server.get_bio().up_ref();
    SSL_set_bio(connection_server, _bio_server.get_bio(), _bio_server.get_bio());
    SSL_set_app_data(connection_server, &_bio_server);

    _ssl_server.initialize(connection_server);

    SSL_set_max_send_fragment(connection_server, TLS_MAX_FRAGMENT_SIZE);
    SSL_set_mode(connection_server, SSL_MODE_SEND_CLIENTHELLO_TIME);
    SSL_set_app_data(connection_server, this);
}

};
