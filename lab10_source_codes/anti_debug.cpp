#include <sys/ptrace.h>
#include <unistd.h>
#include <iostream>

int main() {
    // Ծրագիրը ստուգում է՝ արդյո՞ք իրեն կպած է debugger (GDB/Strace)
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        std::cout << "Debugger detected! Stopping execution..." << std::endl;
        return 1;
    }
    
    // Եթե միջավայրը անվտանգ է (debugger չկա)
    std::cout << "Safe execution environment. Proceeding..." << std::endl;
    return 0;
}
