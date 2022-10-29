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
#ifndef __manager_hpp__
#define __manager_hpp__

#include <cstdint>
#include <unordered_set>

#include <jinx/macros.hpp>
#include <jinx/record.hpp>

#include <jinx/usb/usb.hpp>
#include <jinx/dbus/dbus.hpp>

#include "async.hpp"

#define GET_OPTION(t, n) (_manager->get_config().check<jinx::record::RecordImmediate<t>>(n)->get_value())

namespace fingerpp {

class Manager;
struct USBDeviceInfo;

typedef void (*USBHotplugCallback)(Manager *, USBDeviceInfo* dev_info, libusb_device* device, libusb_device_descriptor* desc, bool connected);

struct USBDeviceInfo {
    uint16_t _vendor{0};
    uint16_t _product{0};
    USBHotplugCallback _callback{nullptr};
    bool _attached{false};
    USBDeviceInfo* _next{nullptr};
};

class Manager {
protected:
    jinx::Loop& _loop;
    AsyncDBus& _dbus;
    AsyncUSB& _usb;
    jinx::record::RecordCategory& _config;

    libusb_hotplug_callback_handle _hotplug_handle{};

    std::unordered_set<std::string> _devices{};

    size_t _next_id{0};

    bool _running{false};

public:
    Manager(jinx::Loop& loop, AsyncDBus& dbus, AsyncUSB& usb, jinx::record::RecordCategory& config) 
    :_loop(loop), _dbus(dbus), _usb(usb), _config(config)
    {
        libusb_hotplug_register_callback(
            _usb, 
            LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, 
            LIBUSB_HOTPLUG_ENUMERATE, 
            LIBUSB_HOTPLUG_MATCH_ANY, 
            LIBUSB_HOTPLUG_MATCH_ANY, 
            LIBUSB_HOTPLUG_MATCH_ANY, 
            hotplug_callback, this, 
            &_hotplug_handle);
    }

    ~Manager() {
        libusb_hotplug_deregister_callback(_usb, _hotplug_handle);
    }

    JINX_NO_COPY_NO_MOVE(Manager);

    jinx::Loop& get_loop() { return _loop; }
    AsyncDBus& get_dbus() { return _dbus; }
    AsyncUSB& get_usb() { return _usb; }
    jinx::record::RecordCategory& get_config() { return _config; }

    const std::unordered_set<std::string>& get_devices() const { return _devices; }

    std::string register_device() {
        std::string path{"/net/reactivated/Device/"};
        path.append(std::to_string(_next_id));
        _next_id += 1;
        _devices.emplace(path);
        return path;
    }

    void unregister_device(const std::string& path) {
        auto iter = _devices.find(path);
        if (iter != _devices.end()) {
            _devices.erase(iter);
        }
    }

    void start();

    static int hotplug_callback(libusb_context* ctx, libusb_device* device, libusb_hotplug_event event, void* data);

    static void add_usb_device(USBDeviceInfo* device);
};

}

#endif
