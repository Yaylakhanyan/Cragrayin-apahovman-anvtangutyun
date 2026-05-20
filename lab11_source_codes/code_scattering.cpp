#include <iostream>

// Ֆունկցիաների բաժանում և ցրում (Scattering)
// Ծրագրի տրամաբանությունը կտորների է բաժանվում և կանչվում ֆունկցիաների զանգվածի միջոցով
int step_one(int x) { 
    return x + 1; 
}

int step_two(int x) { 
    return x * 2; 
}

int main() {
    std::cout << "--- Procedure Scattering ---" << std::endl;

    // Ֆունկցիայի ցուցիչների (function pointers) զանգված
    int (*functions[])(int) = { step_one, step_two };

    int input_val = 5;
    
    // Կանչում ենք հաջորդաբար զանգվածի միջոցով, ինչը խիստ բարդացնում է 
    // Ghidra-ում կամ IDA-ում կառավարման հոսքի (Control Flow Graph) գծագրումը
    int step1_res = functions[0](input_val);  // step_one(5) -> 6
    int final_res = functions[1](step1_res); // step_two(6) -> 12

    std::cout << "Final Scattered Result: " << final_res << std::endl;
    return 0;
}
