#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

// Պլատֆորմից կախված գրադարանների ներմուծում scan-ի համար
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace std;
namespace fs = std::filesystem;

// 1. USB և DVD սարքերի որոնում (scan)
void scanDrives() {
    cout << "Որոնվում են միացված USB կրիչները ... \n";
    cout << "--------------------------\n";

#ifdef _WIN32
    DWORD logicalDrives = GetLogicalDrives();
    bool isFound = false;
    for (int i = 0; i < 26; ++i) {
        if (logicalDrives & (1 << i)) {
            char dName[] = { static_cast<char>('A' + i), ':', '\\', '\0' };
            UINT driveType = GetDriveTypeA(dName);
            if (driveType == DRIVE_REMOVABLE) {
                cout << "Հայտնաբերված USB կրիչ: " << dName << "\n";
                isFound = true;
            } else if (driveType == DRIVE_CDROM) {
                cout << "Հայտնաբերված DVD սարք: " << dName << "\n";
                isFound = true;
            }
        }
    }
    if (!isFound) cout << "Արտաքին կրիչներ չեն գտնվել:\n";
#else
    ifstream mountFile("/proc/mounts");
    string mountLine;
    bool isFound = false;
    while (getline(mountFile, mountLine)) {
        bool hasMedia = (mountLine.find("/media/") != string::npos);
        bool hasRunMedia = (mountLine.find("/run/media/") != string::npos);
        
        if (hasMedia || hasRunMedia) {
            size_t startPos = mountLine.find("/");
            size_t endPos = mountLine.find(" ", startPos);
            if (startPos != string::npos && endPos != string::npos) {
                cout << "Հայտնաբերված արտաքին կրիչ: " << mountLine.substr(startPos, endPos - startPos) << "\n";
                isFound = true;
            }
        }
    }
    if (!isFound) cout << "Արտաքին կրիչներ չեն գտնվել:\n";
#endif
    cout << "--------------------------\n";
}

// 2. Գաղտնագրման և վերծանման հիմնական շարժիչ (Մոդիֆիկացված XOR)
bool processFile(const string& filePath, const string& secretKey, bool doEncrypt) {
    ifstream inputFile(filePath, ios::binary);
    if (!inputFile) return false;

    string outputName = doEncrypt ? (filePath + ".encrypted") : filePath.substr(0, filePath.find(".encrypted"));
    ofstream outputFile(outputName, ios::binary);
    if (!outputFile) return false;

    char byteData;
    int index = 0;
    size_t keyLen = secretKey.size();
    
    while (inputFile.get(byteData)) {
        char currentKeyChar = secretKey[index % keyLen];
        // Բայթ առ բայթ գաղտնագրում
        byteData = byteData ^ (currentKeyChar + (index % 256));
        outputFile.put(byteData);
        index++;
    }

    inputFile.close();
    outputFile.close();

    // Հեռացնում ենք օրիգինալ ֆայլը
    fs::remove(filePath);
    return true;
}

// 3. Առանձին ֆայլային գործողություններ
void encryptFile(string targetFile, string passKey) {
    if (processFile(targetFile, passKey, true)) {
        cout << "Ֆայլը հաջողությամբ գաղտնագրվեց: " << targetFile << ".encrypted\n";
    } else {
        cout << "Սխալ՝ ֆայլը չի գտնվել:\n";
    }
}

void decryptFile(string targetFile, string passKey) {
    if (processFile(targetFile, passKey, false)) {
        cout << "Ֆայլը հաջողությամբ վերծանվեց: " << targetFile.substr(0, targetFile.find(".encrypted")) << "\n";
    } else {
        cout << "Սխալ՝ ֆայլը չի գտնվել:\n";
    }
}

// 4. Պանակի (USB) պաշտպանություն + Լոգերի ֆայլի գեներացում
void protectFolder(string dirPath, string passKey) {
    int allFilesCount = 0;
    int successCount = 0;

    cout << "Պաշտպանում եմ թղթապանակը/USB-ն: " << dirPath << "\n";
    cout << "--------------------------\n";

    for (const auto& item : fs::recursive_directory_iterator(dirPath)) {
        if (fs::is_regular_file(item)) {
            allFilesCount++;
            string extension = item.path().extension().string();
            string name = item.path().filename().string();
            
            if (extension != ".encrypted" && name != "protect_config.txt") {
                if (processFile(item.path().string(), passKey, true)) {
                    cout << "Գաղտնագրվեց: " << item.path().string() << ".encrypted\n";
                    successCount++;
                }
            }
        }
    }

    // Կոնֆիգուրացիոն ֆայլի ստեղծում
    ofstream confFile(dirPath + "/protect_config.txt");
    if(confFile) {
        confFile << "Status: PROTECTED\n";
        confFile << "Encrypted Files Count: " << successCount << "\n";
        confFile << "Encryption Mode: Stream Mode (Modified XOR)\n";
        confFile.close();
    }

    cout << "--------------------------\n";
    cout << "Պաշտպանությունն ավարտվեց:\n";
    cout << "Գաղտնագրվեց " << successCount << " ֆայլ " << allFilesCount << "-ից\n";
}

// 5. Պանակի վերականգնում + Լոգերի ֆայլի մաքրում
void unprotectFolder(string dirPath, string passKey) {
    int restoredCount = 0;

    cout << "Վերականգնում եմ թղթապանակը: " << dirPath << "\n";

    for (const auto& item : fs::recursive_directory_iterator(dirPath)) {
        if (fs::is_regular_file(item)) {
            if (item.path().extension() == ".encrypted") {
                if (processFile(item.path().string(), passKey, false)) {
                    restoredCount++;
                }
            }
        }
    }

    if (fs::exists(dirPath + "/protect_config.txt")) {
        fs::remove(dirPath + "/protect_config.txt");
    }

    cout << "Հաջողությամբ վերականգնվեց " << restoredCount << " ֆայլ:\n";
}

// 6. Ֆայլերի ցուցադրում
void listFiles(string dirPath) {
    cout << "Ֆայլերի ցանկ [" << dirPath << "]:\n";
    for (const auto& item : fs::directory_iterator(dirPath)) {
        if (fs::is_directory(item)) {
            cout << "[DIR]   : " << item.path().filename().string() << "\n";
        } else {
            cout << "[FILE]  : " << item.path().filename().string() << "\n";
        }
    }
}

// Հրամանային տողի ինտերֆեյս (CLI)
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Հրամաններ:\n";
        cout << "  scan             - Փնտրել USB կրիչներ\n";
        cout << "  list <ուղի>      - Ցուցադրել ֆայլերը\n";
        cout << "  protect <ուղի>   - Պաշտպանել ամբողջ USB-ն/պանակը\n";
        cout << "  unprotect <ուղի> - Վերականգնել ամբողջ USB-ն/պանակը\n";
        cout << "  encrypt <ֆայլ>   - Գաղտնագրել 1 ֆայլ\n";
        cout << "  decrypt <ֆայլ>   - Վերծանել 1 ֆայլ\n";
        return 0;
    }

    string userCmd = argv[1];

    if (userCmd == "scan") {
        scanDrives();
    }
    else if (userCmd == "encrypt" && argc == 3) {
        string secret;
        cout << "Մուտքագրեք գաղտնագրման բանալի: ";
        cin >> secret;
        encryptFile(argv[2], secret);
    }
    else if (userCmd == "decrypt" && argc == 3) {
        string secret;
        cout << "Մուտքագրեք բանալի վերծանման համար: ";
        cin >> secret;
        decryptFile(argv[2], secret);
    }
    else if (userCmd == "protect" && argc == 3) {
        string secret;
        cout << "Մուտքագրեք գաղտնագրման բանալի: ";
        cin >> secret;
        protectFolder(argv[2], secret);
    }
    else if (userCmd == "unprotect" && argc == 3) {
        string secret;
        cout << "Մուտքագրեք վերականգնման բանալի: ";
        cin >> secret;
        unprotectFolder(argv[2], secret);
    }
    else if (userCmd == "list" && argc == 3) {
        listFiles(argv[2]);
    }
    else {
        cout << "Սխալ հրաման:\n";
    }

    return 0;
}
