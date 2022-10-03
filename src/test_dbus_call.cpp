#include <chrono>
#include <dbus/dbus-protocol.h>
#include <dbus/dbus-shared.h>
#include <jinx/loop.hpp>

#include "dbus.hpp"

using namespace jinx;

class WorkerService : public AsyncWorker<> {
    raii::asyncdbus::DBusConnection _conn{};
    asyncdbus::DBusSendWithReply _send{};

public:
    WorkerService& operator ()(raii::asyncdbus::DBusConnection& conn) {
        _conn = conn;
        start(&WorkerService::test);
        return *this;
    }

    Async test() {
        auto msg = raii::asyncdbus::DBusMessage{
            dbus_message_new_method_call(
                "org.bluez.obex", 
                "/org/bluez/obex", 
                "org.freedesktop.DBus.Introspectable", 
                "Introspect"
            )
        };
        return *this / _send(_conn, msg, std::chrono::seconds(30)) / &WorkerService::parse;
    }

    Async parse() {
        DBusMessageIter iter{};
        dbus_message_iter_init(_send.get_result(), &iter);
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
            assert(false && "invalid result");
        }
        const char* string = nullptr;
        dbus_message_iter_get_basic(&iter, &string);
        if (string != nullptr) {
            std::cout << string << std::endl;
        }
        return this->done();
    }
};

int main(int argc, const char* argv[])
{
    // EventBackend::set_debug(true);
    EventBackend evb(false);
    Loop loop(evb);

    DBusError error;
    dbus_error_init(&error);

    raii::asyncdbus::DBusConnection conn(
        dbus_bus_get(DBUS_BUS_SESSION, &error)
    );

    if (dbus_error_is_set(&error) != FALSE) {
        jinx_error() << "unable to fetch connection: " << error.message << std::endl; 
        dbus_error_free(&error);
        return -1;
    }

    // int ret = dbus_bus_request_name(
    //     conn, 
    //     "net.reactivated.Fprint", 
    //     0, 
    //     &error);

    // if (dbus_error_is_set(&error) != FALSE) {
    //     jinx_error() << "dbus_bus_request_name failed: " << error.message << std::endl; 
    //     dbus_error_free(&error);
    //     return -1;
    // }
    
    asyncdbus::AsyncDBus dbus{evb, conn};

    loop.spawn<WorkerService>(conn);

    loop.run();
    return 0;
}
