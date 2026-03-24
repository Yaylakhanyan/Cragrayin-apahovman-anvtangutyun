#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace std;
namespace fs = std::filesystem;

void scanDrives() {
    cout << "Որոնվում են միացված USB կրիչները...\n";
#ifndef _WIN32
    ifstream mounts("/proc/mounts");
    string line;
    bool found = false;
    while (getline(mounts, line)) {
        if (line.find("/media/") != string::npos || line.find("/run/media/") != string::npos) {
            size_t start = line.find("/");
            size_t end = line.find(" ", start);
            if (start != string::npos && end != string::npos) {
                cout << "Հայտնաբերված կրիչ: " << line.substr(start, end - start) << "\n";
                found = true;
            }
        }
    }
    if (!found) cout << "Արտաքին կրիչներ չեն գտնվել:\n";
#endif
}

bool processFile(string path, string key, bool encrypt) {
    ifstream in(path, ios::binary);
    if (!in) return false;

    string outName = encrypt ? path + ".encrypted" : path.substr(0, path.find(".encrypted"));
    ofstream out(outName, ios::binary);
    
    char c;
    int i = 0;
    while (in.get(c)) {
        // Մոդիֆիկացված XOR՝ անվտանգությունը մեծացնելու համար
        char keyChar = key[i % key.size()];
        c = c ^ (keyChar + (i % 256));
        out.put(c);
        i++;
    }
    in.close();
    out.close();

    fs::remove(path); // Բնօրինակի հեռացում
    return true;
}

void protectFolder(string path, string key) {
    int count = 0;
    for (auto& p : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(p) && p.path().extension() != ".encrypted") {
            if (processFile(p.path().string(), key, true)) count++;
        }
    }
    
    ofstream config(path + "/protect_config.txt");
    if(config) config << "Status: PROTECTED\nFiles Encrypted: " << count << "\n";
    
    cout << "Պաշտպանությունն ավարտվեց: Գաղտնագրվեց " << count << " ֆայլ:\n";
}

void unprotectFolder(string path, string key) {
    int count = 0;
    for (auto& p : fs::recursive_directory_iterator(path)) {
        if (p.path().extension() == ".encrypted") {
            if (processFile(p.path().string(), key, false)) count++;
        }
    }
    if (fs::exists(path + "/protect_config.txt")) fs::remove(path + "/protect_config.txt");
    cout << "Վերականգնվեց " << count << " ֆայլ:\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Հրամաններ: scan, protect <ուղի>, unprotect <ուղի>\n";
        return 0;
    }
    string cmd = argv[1];

    if (cmd == "scan") scanDrives();
    else if (cmd == "protect" && argc == 3) {
        string key; cout << "Մուտքագրեք բանալի: "; cin >> key;
        protectFolder(argv[2], key);
    }
    else if (cmd == "unprotect" && argc == 3) {
        string key; cout << "Մուտքագրեք բանալի: "; cin >> key;
        unprotectFolder(argv[2], key);
    }
    return 0;