#include <chrono>
#include <dbus/dbus-protocol.h>
#include <dbus/dbus-shared.h>
#include <jinx/loop.hpp>

#include "dbus.hpp"
#include "jinx/awaitable.hpp"

using namespace jinx;
using namespace dbus;

class WorkerService : public DBusObject {
    dbus::DBusSend _send_message{};

public:
    WorkerService() {
        add_node("/test/example/server/Test", [&](DBusNode& node){
            node.add_interface("test.example.server.Test", [&](DBusInterface& iface){
                iface.add_method("Echo", "s", "s", &WorkerService::handle_echo);
                iface.add_signal("StatusChanged", "");
            });
        });
    }

    auto& operator ()(raii::dbus::DBusConnection& conn) {
        return DBusObject::operator()(conn);
    }

protected:
    void finalize() override {
        DBusObject::finalize();
    }

    Async handle_error() override {
        auto state = DBusObject::handle_error();
        // if (a == ControlState::Raise) {
        //     const auto& ec = get_error();
        //     if (ec.category() == wait_catgory() 
        //         and static_cast<int>(AsyncWaitError::Timeout) == ec.value())
        //     {
        //         counter += 1;
        //         return done();
        //     }
        // }
        return state;
    }

    jinx::Async handle_echo() {
        auto& msg = get_message();
        const char* hello = "hello";
        raii::dbus::DBusMessage reply(dbus_message_new_method_return(msg));
        DBusMessageIter iter{};
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &hello);
        return *this / _send_message(_connection, reply) / &WorkerService::run;
    }
};

int main(int argc, const char* argv[])
{
    // EventBackend::set_debug(true);
    EventBackend evb(false);
    Loop loop(evb);

    DBusError error;
    dbus_error_init(&error);

    raii::dbus::DBusConnection conn(
        dbus_bus_get(DBUS_BUS_SESSION, &error)
    );

    if (dbus_error_is_set(&error) != FALSE) {
        jinx_error() << "unable to fetch connection: " << error.message << std::endl; 
        dbus_error_free(&error);
        return -1;
    }

    int ret = dbus_bus_request_name(
        conn, 
        "test.example.server", 
        DBUS_NAME_FLAG_REPLACE_EXISTING, 
        &error);

    if (dbus_error_is_set(&error) != FALSE) {
        jinx_error() << "dbus_bus_request_name failed: " << error.message << std::endl; 
        dbus_error_free(&error);
        return -1;
    }
    
    dbus::dbus dbus{evb, conn};

    loop.spawn<WorkerService>(conn);

    loop.run();
    return 0;
}
