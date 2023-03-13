#ifndef BINARY_HPP
#define BINARY_HPP

#include <string>
#include <vector>

/** Class for helping with binary operations in BND.hpp library **/

class Binary {
public:
    //Binary();
    static std::string get_file(const std::string& path);
    static std::vector<unsigned char> file_to_uchar(const std::string& str);
    static std::string uchar_to_file(std::vector<unsigned char>& data); // maybe const std::vector <uchar>& ?
    static uint8_t get_uint8(const std::vector<unsigned char>& source, int offset);
    static uint16_t get_uint16(const std::vector<unsigned char>& source, int offset);
    static uint32_t get_uint32(const std::vector<unsigned char>& source, int offset);
    static std::string get_string(const std::vector<unsigned char>& source, int offset);
    static std::vector<unsigned char> get_block(const std::vector<unsigned char>& source, int offset, int block_size);
};

#endif // BINARY_HPP
