#include <iostream>

int main() {
    // Օրինակային փոփոխական
    int user_input;
    std::cout << "Enter a number: ";
    std::cin >> user_input;

    // Պաշտպանվող հիմնական կոդը
    if (user_input > 10) {
        // Opaque Predicate (Անթափանց պրեդիկատ)
        // (x * x) >= 0 պայմանը ՄԻՇՏ ճիշտ է ցանկացած ամբողջ թվի համար, 
        // սակայն դեզասեմբլերում (Ghidra/IDA) այն կստեղծի լրացուցիչ բարդ ճյուղավորումներ:
        int x = user_input + 5;
        if ((x * x) >= 0) {
            std::cout << "Access Granted! (Secure Operation Executed)" << std::endl;
        } else {
            // Այս հատվածը ԵՐԲԵՔ չի կատարվի, բայց խճճում է վերլուծողին
            std::cout << "Error: Critical system failure!" << std::endl;
        }
    } else {
        std::cout << "Access Denied!" << std::endl;
    }

    return 0;
}
