#include <iostream>

// Մեթոդ 1: Dummy Parameters (Կեղծ պարամետրեր)
// Ֆունկցիան կատարում է պարզ գումարում, բայց վերլուծողին շփոթեցնելու համար ունի ավելորդ փոփոխականներ
int obf_add_dummy(int a, int b, int fake1, int fake2) {
    // fake1-ը և fake2-ը պարզապես անտեսվում են
    return a + b;
}

// Մեթոդ 2: Packed Parameters (Փաթեթավորված պարամետրեր)
// Երկու 16-բիթանոց կարճ թվեր (short) թաքցվում և փոխանցվում են մեկ 32-բիթանոց ամբողջ թվի (int) մեջ
int obf_add_packed(int packed) {
    short a = (packed >> 16) & 0xFFFF; // Ստանում ենք առաջին թիվը (բարձր բիթերից)
    short b = packed & 0xFFFF;         // Ստանում ենք երկրորդ թիվը (ցածր բիթերից)
    return a + b;
}

int main() {
    std::cout << "--- Argument Count Obfuscation ---" << std::endl;

    // 1. Dummy parameters դեմոնստրացիա
    int res1 = obf_add_dummy(5, 3, 999, 12345);
    std::cout << "Dummy Method Result (5 + 3): " << res1 << std::endl;

    // 2. Packed parameters դեմոնստրացիա (Օրինակ՝ 5 և 3 թվերը)
    // 5-ը շարժում ենք ձախ 16 բիթով և միավորում 3-ի հետ
    int packed_value = (5 << 16) | (3 & 0xFFFF); 
    int res2 = obf_add_packed(packed_value);
    std::cout << "Packed Method Result (5 + 3): " << res2 << std::endl;

    return 0;
}
