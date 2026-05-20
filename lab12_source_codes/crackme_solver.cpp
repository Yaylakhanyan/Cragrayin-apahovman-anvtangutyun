#include <iostream>

using namespace std;

int main() {
    // Կոդավորված բանալիները crackme ծրագրից
    int key[] = {72, 29, 7, 0, 91};
    
    cout << "--- Crackme Password Solver ---" << endl;
    cout << "Recovered Password: ";
    
    // Հակադարձ գործողություն՝ input = key XOR 0x55
    for (int i = 0; i < 5; i++) {
        char decrypted_char = key[i] ^ 0x55;
        cout << decrypted_char;
    }
    cout << endl;
    
    return 0;
}
