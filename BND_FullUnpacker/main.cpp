#include <iostream>
#include <filesystem>

#include "BND.h"

namespace fs = std::filesystem;

void unpack_full_archive(BND& archive) {
    archive.extract_literally_everything_dont_use_ever(archive);
}

int main() {
    std::cout << "Dangerous BND Full Unpacker started!\n";
    std::cout << "Please enter the path to the BND archive: ";
    fs::path archive_path;
    std::cin >> archive_path;

    BND archive;
    try {
        if (!archive.load(archive_path.string())) {
            "archive.load(...) claims the file was not loaded due to some error\n";
            std::cout << "Aborting the program\n";
            exit(1);
        }
    }
    catch (...) {
        std::cout << "Errors occured, please check the library's output!";
        exit(1);
    }

    bool confirmation;

    std::cout << "Unpack the archive and report? (1 for yes)\n";
    std::cin >> confirmation;
    if (std::cin.fail()) {
        std::cout << "Wrong input, quitting.\n";
        exit(1);
    }

    if (!confirmation) {
        std::cout << "No action will be taken, exiting...\n";
        return;
    }

    
    try {
        unpack_full_archive(archive);
    }
    catch (...) {
        std::cout << "Errors occured, please check the library's output!";
        exit(1);
    }
    
    std::cout << "The archive should have been extracted by now. Exiting...\n";

}