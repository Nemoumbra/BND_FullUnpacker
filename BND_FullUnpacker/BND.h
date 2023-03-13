#ifndef BND_HPP
#define BND_HPP

#include <string>
#include <vector>

/** Class for reading and manipulating Patapon BND files **/

class BND {
public:
    int type = 0; ///0 = regular bnd, 1 = with external dictionary
    std::string original_name = "";
    std::string data_file = "";

    uint8_t version = 0; ///Version integer found at 0x4
    int empty_blocks = 0; ///Amount of empty 0x10 blocks from 0x24 to first CRC entry
    bool encrypt = false;

    struct File {
        int8_t level;
        std::string name;
        std::vector<unsigned char> data;
        // store the id here?
        ///debug values, mostly used only after loading file
        uint32_t dbg_data_offset;
    };

    std::vector<File> files;

    BND();
    bool load(const std::string& file, bool log = true);
    bool load(const std::string& dict_file, const std::string& ddata_file, bool encrypted);
    bool loadFromMem(const std::string& filename, std::vector<unsigned char>& file, bool log = true);
    uint32_t count_files(); // This should be const
    uint32_t count_entries(); // This should be const
    std::string get_full_name(int id); // This should be const
    void replace_file(int id, const std::string& path);
    int get_type(int id); // This should be const
    void list_all_files(); // This should be const
    void list_sorted_via_offset(); // This should be const
    void extract(int id, std::string destination = ""); // This should be const
    //void extract_gzip(int id); // That's not the best solution to comment out the definition, but leave the declaration intact
    void extract_all(); // This should be const
    void extract_literally_everything_dont_use_ever(BND bnd_handle); // This should be const
    void remove_file(int id);
    void add_file(int id, const std::string& path, bool folder = false);
    void save(const std::string& path);
    void save(const std::string& dict, const std::string& data);
};

#endif // BND_HPP
