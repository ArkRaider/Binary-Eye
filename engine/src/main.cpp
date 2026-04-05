#include "Analyzer.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pe_file>" << std::endl;
        return 1;
    }

    Analyzer analyzer(argv[1]);
    if (!analyzer.analyze()) {
        std::cerr << "Analysis failed." << std::endl;
        return 1;
    }

    std::cout << analyzer.get_report_json().dump(4) << std::endl;
    return 0;
}
