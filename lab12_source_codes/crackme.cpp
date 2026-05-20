#include <iostream>
#include <string>

using namespace std;

// Օբֆուսկացված ստուգման ֆունկցիա
bool check_password(string input) {
    // Գաղտնագրված ճիշտ գաղտնաբառի XOR արժեքները
    int key[] = {72, 29, 7, 0, 91}; 
    
    if (input.length() != 5)
        return false;
        
    for (int i = 0; i < 5; i++) {
        // Յուրաքանչյուր նիշ ենթարկվում է XOR 0x55 գործողության և համեմատվում բանալու հետ
        if ((input[i] ^ 0x55) != key[i])
            return false;
    }
    return true;
}

int main() {
    string pass;
    cout << "Enter password: ";
    cin >> pass;
    
    if (check_password(pass)) {
        cout << "Access Granted! Welcome back." << endl;
    } else {
        cout << "Access Denied! Intruder detected." << endl;
    }
    return 0;
}
