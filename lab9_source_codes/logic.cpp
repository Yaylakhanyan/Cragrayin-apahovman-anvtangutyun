#include <iostream>

int main() {
    int x = 0;

    // Ստուգում ենք պայմանը Binary Patching-ի համար
    if (x == 5) {
        std::cout << "Correct" << std::endl;
    } else {
        std::cout << "Wrong" << std::endl;
    }

    return 0;
}
