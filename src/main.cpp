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
#include <syslog.h>
#include <sys/stat.h>

#include <cstring>

#include <jinx/async.hpp>
#include <jinx/libevent.hpp>
#include <jinx/posix.hpp>
#include <jinx/logging.hpp>
#include <jinx/record.hpp>
#include <jinx/argparse.hpp>

#include <jinx/dbus/dbus.hpp>
#include <jinx/usb/usb.hpp>
#include "manager.hpp"

using namespace jinx;
using namespace jinx::record;
using namespace jinx::argparse;
using namespace jinx::dbus;
using namespace jinx::usb;
using namespace fingerpp;

typedef AsyncImplement<libevent::EventEngineLibevent> async;
typedef posix::AsyncIOPosix<libevent::EventEngineLibevent> asyncio;

const std::array<Argument, 6> arguments
{{
    { "bus", "session", 1, 256, "dbus bus. 'system' or 'session'. default 'session'" },
    { "min-area", size_t(120000), size_t(1), size_t(0xFFFFFFFF), "min fingerprint area" },
    { "min-score", float(0.5), float(0.1), float(1.0), "min score" },
    { "data-path", "/var/lib/fprint", 1, 256, "data path" },
    { "filter-before-ssim", false, "filter image before MSSIM" },
    { "debug", false, "debug" }
}};

#define OPT(t, n) config.check<RecordImmediate<t>>(n)->get_value()

int main(int argc, const char* argv[])
{
    ::umask(0600);

    openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_AUTH | LOG_INFO);
    syslog(LOG_AUTH | LOG_INFO, "fingerpp starting");
    
    RecordCategory config{};
    parse_argv(argc, argv, config, arguments.data(), arguments.size());

    DBusError error;
    dbus_error_init(&error);

    auto bus = DBUS_BUS_SESSION;
    if (OPT(std::string, "bus") == "system") {
        bus = DBUS_BUS_SYSTEM;
    }

    if (bus == DBUS_BUS_SESSION) {
        char data_path[PATH_MAX];
        (void)getcwd(data_path, PATH_MAX);
        config.check<RecordImmediate<std::string>>("data-path")->commit(data_path);
    }

    AsyncDBusConnection conn(
        dbus_bus_get(bus, &error)
    );

    if (dbus_error_is_set(&error) != FALSE) {
        jinx_log_error() << "unable to fetch connection: " << error.message << std::endl; 
        dbus_error_free(&error);
        return -1;
    }

    int ret = dbus_bus_request_name(
        conn, 
        "net.reactivated.Fprint", 
        DBUS_NAME_FLAG_REPLACE_EXISTING, 
        &error);

    if (dbus_error_is_set(&error) != FALSE) {
        jinx_log_error() << "dbus_bus_request_name failed: " << error.message << std::endl; 
        dbus_error_free(&error);
        return -1;
    }
    
    libevent::EventEngineLibevent eve(false);
    Loop loop(&eve);

    AsyncDBus dbus{eve, conn};
    AsyncUSB usb{eve};

    Manager manager{loop, dbus, usb, config};

    loop.run();
    return 0;
}
