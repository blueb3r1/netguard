#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdint>
#include <set>
#include <thread>
#include <mutex>
#include "auth_test.cpp"
#include <vector>
using namespace std;

string decode_addr(const string &hex_addr)
{
    size_t colon = hex_addr.find(':');
    string hex_ip = hex_addr.substr(0, colon);
    string hex_port = hex_addr.substr(colon + 1);
    uint32_t ip = stoul(hex_ip, nullptr, 16);
    uint32_t port = stoul(hex_port, nullptr, 16);

    uint32_t b1 = ip & 0xFF;
    uint32_t b2 = (ip >> 8) & 0xFF;
    uint32_t b3 = (ip >> 16) & 0xFF;
    uint32_t b4 = (ip >> 24) & 0xFF;

    return to_string(b1) + '.' + to_string(b2) + '.' + to_string(b3) + '.' + to_string(b4) + ':' + to_string(port);
}

set<string> scan_listen_port()
{
    // vector<string> files = {"/proc/net/tcp", "/proc/net/tcp6"};
    set<string> active_ports;

    // for (auto& i : files){
    ifstream fin("/proc/net/tcp");
    if (!fin.is_open())
    {
        return active_ports;
    }
    string line;
    getline(fin, line);
    while (getline(fin, line))
    {
        istringstream iss(line);
        string sl, local_addr, rem_addr, state;
        iss >> sl >> local_addr >> rem_addr >> state;
        if (state == "0A")
        {
            active_ports.insert(decode_addr(local_addr));
        }
    }
//}
    return active_ports;
}

void monitor_port()
{
    set<string> known_ports = scan_listen_port();
    while (true)
    {
        this_thread::sleep_for(chrono::seconds(3));
        set<string> current_ports = scan_listen_port();
        for (const string &addr : current_ports)
        {
            if (known_ports.find(addr) == known_ports.end())
            {
                emit_alert("NEW_PORT_DETECTED", "HIGH", "New listening address detected: " + addr);
            }
        }
        known_ports = current_ports;
    }
}

int main()
{
    thread port_thread(monitor_port);
    thread auth_thread(monitor_auth);
    port_thread.join();
    auth_thread.join();
    return 0;
}