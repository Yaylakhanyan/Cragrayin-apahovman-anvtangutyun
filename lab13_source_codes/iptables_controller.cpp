#include <iostream>
#include <cstdlib>
#include <string>

using namespace std;

// Ֆունկցիա՝ iptables հրաման կատարելու համար
void execute_command(const string& cmd) {
    int result = system(cmd.c_str());
    if (result == 0) {
        cout << "[SUCCESS] Executed: " << cmd << endl;
    } else {
        cout << "[ERROR] Failed to execute (Run as root/sudo?): " << cmd << endl;
    }
}

int main() {
    int choice;
    string target_ip, target_port;

    cout << "--- C++ Linux iptables Firewall Controller ---" << endl;
    cout << "1. Block a specific IP address" << endl;
    cout << "2. Block a specific Port" << endl;
    cout << "3. View Current Firewall Rules" << endl;
    cout << "4. Flush (Clear) All Rules" << endl;
    cout << "Enter your choice (1-4): ";
    cin >> choice;

    switch (choice) {
        case 1:
            cout << "Enter IP to block: ";
            cin >> target_ip;
            // DROP կանոն՝ տվյալ IP-ից եկող տրաֆիկը արգելափակելու համար
            execute_command("sudo iptables -A INPUT -s " + target_ip + " -j DROP");
            break;
        case 2:
            cout << "Enter Port to block: ";
            cin >> target_port;
            // DROP կանոն՝ տվյալ TCP պորտ մուտք գործող տրաֆիկի համար
            execute_command("sudo iptables -A INPUT -p tcp --dport " + target_port + " -j DROP");
            break;
        case 3:
            // Ցուցադրել ակտիվ կանոնները
            cout << "\n=== Active iptables Rules ===" << endl;
            system("sudo iptables -L -v -n");
            break;
        case 4:
            // Մաքրել բոլոր կանոնները
            execute_command("sudo iptables -F");
            break;
        default:
            cout << "Invalid choice!" << endl;
    }

    return 0;
}
