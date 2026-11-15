#include <iostream>
#include <cstdio>
#include <string>
#include <mutex>
#include <fstream>
#include <cstdlib>

// #include <ofstream>

using namespace std;

mutex output_mtx;

void emit_alert(const string &event_type, const string &severity, const string &detail)
{
    lock_guard<mutex> lock(output_mtx);
    time_t now = time(nullptr);
    string json = "{\"timestamp\": " + to_string(now) + "\n" +
                  ", \"event_type\": \"" +
                  event_type + "\"" + "\n" +
                  ", \"severity\": \"" +
                  severity + "\"" + "\n" +
                  ", \"detail\": \"" +
                  detail + "\"}";

    cout << json << "\n"
         << flush;
    ofstream log_file("alerts.jsonl", ios::app);
    if (log_file.is_open())
    {
        log_file << json << "\n";
    }
    string cmd = "curl -s -X POST http://127.0.0.1:8000/api/alerts "
                 "-H 'X-API: netguard_lock_2508' "
                 "-H 'Content-Type: application/json' "
                 "-d '" +
                 json + "' > /dev/null 2>&1 &";
    system(cmd.c_str());
}

void monitor_auth()
{
    FILE *pipe = popen("journalctl -f -n 0", "r");
    char buffer[1024];
    int count = 0;
    time_t last_time = time(nullptr);
    const int LEAK_INTERVAL = 30;

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        string line(buffer);
        if (line.find("Failed password") != string::npos || line.find("authentication failure") != string::npos)
        {
            time_t now = time(nullptr);
            int leaked = (now - last_time) / LEAK_INTERVAL;
            if (leaked > 0)
            {
                count = max(0, count - leaked);
                last_time += leaked * LEAK_INTERVAL;
            }
            count++;
            if (count >= 3)
            {
                emit_alert("BRUTE_FORCE", "CRITICAL", "Auth failed 3 times within leak window");
                count = 0;
            }
        }
    }
}