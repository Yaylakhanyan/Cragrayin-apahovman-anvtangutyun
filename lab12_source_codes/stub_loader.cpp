#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>

using namespace std;

vector<char> read_file(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) {
        cerr << "Error: Packed payload not found! Make sure packed_payload.bin exists." << endl;
        exit(1);
    }
    return vector<char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

void xor_crypt(vector<char>& data, char key) {
    for (auto& b : data) {
        b ^= key;
    }
}

int main() {
    cout << "--- Packer Stub Loader Executing ---" << endl;
    
    char key = 0x55; // Նույն բանալին ապագաղտնագրման համար
    
    // 1. Կարդում ենք կոդավորված տվյալները
    vector<char> packed_data = read_file("packed_payload.bin");
    
    // 2. Runtime-ում ապագաղտնագրում ենք (XOR-ի հատկությամբ երկրորդ XOR-ը վերականգնում է բնօրինակը)
    xor_crypt(packed_data, key);
    
    // 3. Գրում ենք ժամանակավոր կատարողական ֆայլ հիշողությունից/սկավառակից
    string temp_output = "./unpacked_temp.bin";
    ofstream outfile(temp_output, ios::binary);
    outfile.write(packed_data.data(), packed_data.size());
    outfile.close();
    
    // 4. Տալիս ենք աշխատեցնելու թույլտվություն (Linux-ի համար)
    string chmod_cmd = "chmod +x " + temp_output;
    system(chmod_cmd.c_str());
    
    cout << "Payload unpacked successfully. Launching target..." << endl;
    cout << "=================================================" << endl;
    
    // 5. Գործարկում ենք ապագաղտնագրված ծրագիրը
    system(temp_output.c_str());
    
    // 6. Անվտանգության համար ջնջում ենք ժամանակավոր ֆայլը աշխատանքից հետո
    string rm_cmd = "rm " + temp_output;
    system(rm_cmd.c_str());
    
    return 0;
}
