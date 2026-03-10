#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <intrin.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

using namespace std;

// =======================
// Hardware ID Class
// =======================
class HardwareID {
public:
    static string GetCpuId() {
        int cpuInfo[4] = { -1 };
        __cpuid(cpuInfo, 1);

        stringstream ss;
        ss << hex << uppercase << setfill('0')
            << setw(8) << cpuInfo[3]
            << setw(8) << cpuInfo[0];

        return ss.str();
    }
};

// =======================
// License Key Generator
// =======================
class LicenseKey {
private:
    static const string Salt;

public:
    static string GenerateKey(const string& hardwareId) {
        string rawData = hardwareId + Salt;

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        string resultHash = "";

        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {

                CryptHashData(hHash,
                    reinterpret_cast<const BYTE*>(rawData.c_str()),
                    rawData.length(), 0);

                DWORD hashLen = 0;
                DWORD hashLenSize = sizeof(DWORD);
                CryptGetHashParam(hHash, HP_HASHSIZE,
                    reinterpret_cast<BYTE*>(&hashLen),
                    &hashLenSize, 0);

                if (hashLen > 0) {
                    BYTE* hashBytes = new BYTE[hashLen];

                    if (CryptGetHashParam(hHash, HP_HASHVAL,
                        hashBytes, &hashLen, 0)) {

                        stringstream ss;
                        for (DWORD i = 0; i < hashLen; i++) {
                            ss << hex << uppercase
                                << setw(2) << setfill('0')
                                << (int)hashBytes[i];
                        }

                        // Վերցնում ենք առաջին 20 նիշը
                        Ժ՝resultHash = ss.str().substr(0, 20);
                    }
                    delete[] hashBytes;
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        return resultHash;
    }
};

const string LicenseKey::Salt = "MySecretLabSalt_CPlusPlus_2024";

// =======================
// License Manager
// =======================
class LicenseManager {
private:
    static const string LicenseFile;

public:
    static void SaveLicense(const string& key) {
        ofstream outFile(LicenseFile);
        if (outFile.is_open()) {
            outFile << key;
            outFile.close();
            cout << "[+] License saved successfully.\n";
        }
    }

    static bool ValidateLicense() {
        ifstream inFile(LicenseFile);

        if (!inFile.is_open()) {
            cout << "[-] License file not found. Activation required.\n";
            return false;
        }

        string savedKey;
        getline(inFile, savedKey);
        inFile.close();

        string currentHardwareId = HardwareID::GetCpuId();
        string expectedKey = LicenseKey::GenerateKey(currentHardwareId);

        if (savedKey == expectedKey) {
            cout << "[+] License is VALID.\n";
            return true;
        }
        else {
            cout << "[-] INVALID license (Hardware mismatch).\n";
            return false;
        }
    }
};

const string LicenseManager::LicenseFile = "license.key";

// =======================
// MAIN FUNCTION
// =======================
int main() {

    cout << "=============================================\n";
    cout << " Software Security - Hardware License System\n";
    cout << "=============================================\n\n";

    // 1. Ստանում ենք Hardware ID
    string hwId = HardwareID::GetCpuId();
    cout << "Hardware ID: " << hwId << endl;

    // 2. Գեներացնում ենք լիցենզիայի բանալի
    string generatedKey = LicenseKey::GenerateKey(hwId);
    cout << "Generated License Key: " << generatedKey << endl;

    cout << "\n---------------------------------------------\n";

    // 3. Սիմուլյացնում ենք ակտիվացումը (պահպանում ֆայլում)
    LicenseManager::SaveLicense(generatedKey);

    // 4. Վավերացնում ենք լիցենզիան մուտք գործելու համար
    cout << "\nValidating license...\n";

    if (LicenseManager::ValidateLicense()) {
        cout << "Access granted. Program started successfully.\n";
    }
    else {
        cout << "Access denied. Program blocked.\n";
    }

    system("pause");
    return 0;
}

