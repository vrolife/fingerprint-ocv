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
#include <sys/inotify.h>
#include <syslog.h>

#include <cstring>
#include <vector>
#include <mutex>

#include <jinx/async.hpp>
#include <jinx/usb/usb.hpp>
#include <jinx/dbus/dbus.hpp>

#include "manager.hpp"

namespace fingerpp {
using namespace jinx;
using namespace jinx::dbus;

class WorkerManager : public AsyncDBusObject {
    fingerpp::Manager* _manager{};

    AsyncDBusSend _send_message{};

public:
    WorkerManager() {
        add_node("/net/reactivated/Fprint/Manager", [&](AsyncDBusNode& node){
            node.add_interface("net.reactivated.Fprint.Manager", [&](AsyncDBusInterface& iface){
                iface.add_method("GetDevices", "", "ao", &WorkerManager::get_devices);
                iface.add_method("GetDefaultDevice", "", "o", &WorkerManager::get_default_device);
            });
        });
    }

    auto& operator ()(AsyncDBusConnection& conn, fingerpp::Manager* manager) {
        _manager = manager;
        return AsyncDBusObject::operator()(conn);
    }

protected:
    Async init() override {
        syslog(LOG_AUTH | LOG_INFO, "namager starting");
        return AsyncDBusObject::init();
    }

    Async get_devices() {
        auto& msg = get_message();
        AsyncDBusMessage reply(dbus_message_new_method_return(msg));
        DBusMessageIter iter{};
        DBusMessageIter sub{};
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "o", &sub);
        for(const auto& path : _manager->get_devices()) {
            const char* string = path.c_str();
            dbus_message_iter_append_basic(&sub, DBUS_TYPE_OBJECT_PATH, &string);
        }
        dbus_message_iter_close_container(&iter, &sub);
        return *this / _send_message(_connection, reply) / &WorkerManager::run;
    }

    Async get_default_device() {
        auto& msg = get_message();
        AsyncDBusMessage reply{};

        if (_manager->get_devices().empty()) {
            reply.reset(dbus_message_new_error(msg, "net.reactivated.Fprint.Error.NoSuchDevice", "no such device"));
        } else {
            reply.reset(dbus_message_new_method_return(msg));
            DBusMessageIter iter{};
            dbus_message_iter_init_append(reply, &iter);
            const char* string = _manager->get_devices().begin()->c_str();
            dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &string);
        }
        return *this / _send_message(_connection, reply) / &WorkerManager::run;
    }
};

static std::mutex _usb_device_lock{};
static USBDevice* _usb_devices{nullptr};

void Manager::add_usb_device(USBDevice* device)
{
    std::lock_guard<std::mutex> lock{_usb_device_lock};

    device->_next = _usb_devices;
    _usb_devices = device;
}

int Manager::hotplug_callback(libusb_context* ctx, libusb_device* device, libusb_hotplug_event event, void* data)
{
    auto* manager = reinterpret_cast<Manager*>(data);
    libusb_device_descriptor desc{};
    libusb_get_device_descriptor(device, &desc);    

    std::lock_guard<std::mutex> lock{_usb_device_lock};

    auto* dev = _usb_devices;
    while (dev != nullptr) {
        if (dev->_vendor == desc.idVendor and dev->_product == desc.idProduct) {
            syslog(LOG_INFO | LOG_AUTH, "usb hotplug: %s: %hx %hx", 
                event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED ? "arrived" : "left", desc.idVendor, desc.idProduct);
            dev->_callback(manager, device, &desc, event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
        }
        dev = dev->_next;
    }
    return 0;
}

void Manager::start()
{
    if (not _running) {
        _running = true;
        get_loop().task_new<WorkerManager>(_dbus.get_connection(), this);
    }
}

}
