#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

// Ֆունկցիա՝ ֆայլը բինար տեսքով կարդալու համար
vector<char> read_file(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) {
        cerr << "Error opening file for reading: " << path << endl;
        exit(1);
    }
    return vector<char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Ֆունկցիա՝ ֆայլը բինար տեսքով գրելու համար
void write_file(const string& path, const vector<char>& data) {
    ofstream file(path, ios::binary);
    file.write(data.data(), data.size());
}

// XOR գաղտնագրում/ապագաղտնագրում (Symmetric Key)
void xor_crypt(vector<char>& data, char key) {
    for (auto& b : data) {
        b ^= key; // Յուրաքանչյուր բայթ ենթարկվում է XOR-ի
    }
}

int main() {
    cout << "--- Toy Packer (Builder) ---" << std::endl;
    
    // Կարդում ենք այն ֆայլը, որը պետք է թաքցնել (օրինակ՝ պարզ hello բինարը)
    // Ուսանողական փորձարկման համար սա կարող է լինել ցանկացած փոքր ֆայլ
    string input_path = "target_program"; 
    char key = 0x55; // Գաղտնի բանալի
    
    vector<char> file_data = read_file(input_path);
    
    // XOR-ով կոդավորում ենք ֆայլի պարունակությունը
    xor_crypt(file_data, key);
    
    // Պահպանում ենք կոդավորված տվյալները նոր ֆայլում
    write_file("packed_payload.bin", file_data);
    
    cout << "Successfully packed and encrypted '" << input_path << "' into 'packed_payload.bin'" << endl;
    return 0;
}
