#include "BND.h"
#include "Binary.h"
#include "CRC.h"
#include "libP3Hash.h"

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <chrono>
#include <sstream>
#include <windows.h>

#include <cctype>

//using namespace std;

std::ifstream::pos_type filesize(const std::string& filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

void logger(uint8_t color, std::string header, std::string message) {
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(handle, color);
    std::cout << header;

    uint8_t hibyte = (color & 0xf0) >> 4;
    uint8_t lobyte = (color & 0x0f);
    color = lobyte << 4 | hibyte;

    SetConsoleTextAttribute(handle, color);
    std::cout << " " << message << std::endl;

    SetConsoleTextAttribute(handle, 7);
}

std::string to_hstring(int a)
{
    std::stringstream ss;
    ss << std::hex << a;
    return ss.str();
}

BND::BND() {

}

bool BND::load(const std::string& file, bool log) {
    auto t_start = std::chrono::steady_clock::now();

    if (log)
        logger(0x20, "[BND]", "Attempting to read: " + file);
    //std::cout << "[BND] Attempting to read: " << file << endl;

    original_name = file;

    std::vector<unsigned char> data = Binary::file_to_uchar(Binary::get_file(file));

    if (data.size() <= 0)
        return false;

    if (Binary::get_uint8(data, 0x0) != 'B')
        return false;

    if (Binary::get_uint8(data, 0x1) != 'N')
        return false;

    if (Binary::get_uint8(data, 0x2) != 'D')
        return false;

    version = Binary::get_uint8(data, 0x4);

    uint32_t p_info = Binary::get_uint32(data, 0x10);
    uint32_t p_file = Binary::get_uint32(data, 0x14);

    uint32_t p_entries = Binary::get_uint32(data, 0x24);

    if (p_entries <= 0)
        return false;

    uint32_t test = 0x0;

    while (test == 0x0) {
        test = Binary::get_uint32(data, 0x28 + (empty_blocks * 0x10));

        if (test == 0x0)
            ++empty_blocks;
    }

    p_entries -= empty_blocks;

    uint32_t offset = 0x0; ///reading offset

    if (!((int(version) >= 1) && (int(version) <= 5)))
        return false;

    if (log)
        logger(0x20, "[BND]", "Version: " + std::to_string(int(version)));
    if (log)
        logger(0x20, "[BND]", "Info offset at: 0x" + to_hstring(p_info));
    if (log)
        logger(0x20, "[BND]", "File offset at: 0x" + to_hstring(p_file));

    for (int i = 0; i < p_entries; ++i) {
        //std::cout << std::hex << p_info+offset << " " << p_file << std::dec << endl;
        //logger(0x20, "[BND]", "Reading entry "+to_string(i+1)+"/"+to_string(p_entries));

        File temp;

        uint32_t p_crc = Binary::get_uint32(data, p_info + offset + 3);

        if (p_crc != 0x0) {
            std::vector<unsigned char> crc_block = Binary::get_block(data, p_crc, 0x10);
            uint32_t f_pointer = Binary::get_uint32(crc_block, 0x8);
            uint32_t f_size = Binary::get_uint32(crc_block, 0xC);

            //logger(0x20, "[BND]", "F_pointer: 0x"+to_hstring(f_pointer)+" F_size: 0x"+to_hstring(f_size));

            if (f_size >= 0x20000000)
                f_size -= 0x20000000;

            temp.level = int8_t(static_cast<unsigned char>(Binary::get_uint8(data, p_info + offset))); // Why are there 2 conversions?

            if (f_pointer < data.size())
                temp.data = Binary::get_block(data, f_pointer, f_size);

            temp.name = Binary::get_string(data, p_info + offset + 7);

            temp.dbg_data_offset = f_pointer;

            files.push_back(temp);

            offset += 7 + temp.name.size() + 1;
        }
    }

    if (log)
        logger(0x20, "[BND]", "File loaded successfully.");

    //  Insert the code that will be timed

    auto t_end = std::chrono::steady_clock::now();

    // Store the time difference between start and end
    auto diff = t_end - t_start;

    float diff_sec = std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
    if (log)
        logger(0x20, "[BND]", "Time taken: " + std::to_string(diff_sec / float(1000)) + " seconds");

    return true;
}

bool BND::load(const std::string& dict_file, const std::string& ddata_file, bool encrypted) {
    type = 1;

    auto t_start = std::chrono::steady_clock::now();

    original_name = dict_file;
    data_file = ddata_file;

    logger(0x20, "[BND]", "Attempting to read: " + original_name + " and " + data_file);

    std::vector<unsigned char> data = Binary::file_to_uchar(Binary::get_file(dict_file));
    std::vector<unsigned char> file_data = Binary::file_to_uchar(Binary::get_file(data_file));

    if (data.size() <= 0)
        return false;

    version = Binary::get_uint8(data, 0x4);

    uint32_t p_info = Binary::get_uint32(data, 0x10);
    uint32_t p_file = Binary::get_uint32(data, 0x14);

    logger(0x20, "[BND]", "Version: " + std::to_string(int(version)));
    logger(0x20, "[BND]", "Info offset at: 0x" + to_hstring(p_info));
    logger(0x20, "[BND]", "File offset at: 0x" + to_hstring(p_file));

    uint32_t test = 0x0;

    while (test == 0x0) {
        test = Binary::get_uint32(data, 0x28 + (empty_blocks * 0x10));

        if (test == 0x0)
            empty_blocks++;
    }

    uint32_t offset = 0x0; ///reading offset

    //std::cout << "Empty blocks: " << empty_blocks << endl;

    if (encrypted) {
        //std::cout << "Decrypting..." << endl;
        logger(0x90, "[P3Hash]", "Decrypting the data file...");
        encrypt = true;
    }

    while ((p_info + offset < filesize(dict_file)) && (test != 0x0)) {
        File temp;

        uint32_t p_crc = Binary::get_uint32(data, p_info + offset + 3);

        std::vector<unsigned char> crc_block = Binary::get_block(data, p_crc, 0x10);
        uint32_t f_pointer = Binary::get_uint32(crc_block, 0x8);
        uint32_t f_size = Binary::get_uint32(crc_block, 0xC);

        //std::cout << "Crc:" << std::hex << p_crc << " " << f_pointer << " " << f_size << endl;
        if (f_size >= 0x20000000)
            f_size -= 0x20000000;

        temp.level = int8_t(static_cast<unsigned char>(Binary::get_uint8(data, p_info + offset)));
        temp.data = Binary::get_block(file_data, f_pointer, f_size);
        temp.name = Binary::get_string(data, p_info + offset + 7);

        temp.dbg_data_offset = f_pointer;

        if (encrypted) {
            std::vector<unsigned char> decrypted;

            for (int i = 0; i < temp.data.size(); i += 16) {
                uint32_t a = Binary::get_uint32(temp.data, i);
                uint32_t b = Binary::get_uint32(temp.data, i + 4);
                uint32_t c = Binary::get_uint32(temp.data, i + 8);
                uint32_t d = Binary::get_uint32(temp.data, i + 12);

                std::vector<uint32_t> v_block = { a,b,c,d };

                libP3Hash handle;
                v_block = handle.decryptBlock(v_block);

                decrypted.push_back((v_block[0] >> 24) & 0xff);
                decrypted.push_back((v_block[0] >> 16) & 0xff);
                decrypted.push_back((v_block[0] >> 8) & 0xff);
                decrypted.push_back(v_block[0] & 0xff);

                decrypted.push_back((v_block[1] >> 24) & 0xff);
                decrypted.push_back((v_block[1] >> 16) & 0xff);
                decrypted.push_back((v_block[1] >> 8) & 0xff);
                decrypted.push_back(v_block[1] & 0xff);

                decrypted.push_back((v_block[2] >> 24) & 0xff);
                decrypted.push_back((v_block[2] >> 16) & 0xff);
                decrypted.push_back((v_block[2] >> 8) & 0xff);
                decrypted.push_back(v_block[2] & 0xff);

                decrypted.push_back((v_block[3] >> 24) & 0xff);
                decrypted.push_back((v_block[3] >> 16) & 0xff);
                decrypted.push_back((v_block[3] >> 8) & 0xff);
                decrypted.push_back(v_block[3] & 0xff);
            }

            temp.data = decrypted; // std::move(decrypted) ?
        }

        files.push_back(temp);

        offset += 7 + temp.name.size() + 1;

        test = Binary::get_uint32(data, p_info + offset);
    }

    logger(0x20, "[BND]", "File loaded successfully.");

    //  Insert the code that will be timed

    auto t_end = std::chrono::steady_clock::now();

    // Store the time difference between start and end
    auto diff = t_end - t_start;

    float diff_sec = std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
    logger(0x20, "[BND]", "Time taken: " + std::to_string(diff_sec / float(1000)) + " seconds");

    return true;
}

bool BND::loadFromMem(const std::string& filename, std::vector<unsigned char>& file, bool log) {
    auto t_start = std::chrono::steady_clock::now();

    if (log)
        logger(0x20, "[BND]", "Attempting to read: " + filename);
    //std::cout << "[BND] Attempting to read: " << file << endl;

    original_name = filename;

    std::vector<unsigned char> data = file;

    if (data.size() <= 0)
        return false;

    if (Binary::get_uint8(data, 0x0) != 'B')
        return false;

    if (Binary::get_uint8(data, 0x1) != 'N')
        return false;

    if (Binary::get_uint8(data, 0x2) != 'D')
        return false;

    version = Binary::get_uint8(data, 0x4);

    uint32_t p_info = Binary::get_uint32(data, 0x10);
    uint32_t p_file = Binary::get_uint32(data, 0x14);

    uint32_t p_entries = Binary::get_uint32(data, 0x24);

    if (p_entries <= 0)
        return false;

    uint32_t test = 0x0;

    while (test == 0x0) {
        test = Binary::get_uint32(data, 0x28 + (empty_blocks * 0x10));

        if (test == 0x0)
            ++empty_blocks;
    }

    p_entries -= empty_blocks;

    uint32_t offset = 0x0; ///reading offset

    if (!((int(version) >= 1) && (int(version) <= 5)))
        return false;

    if (log)
        logger(0x20, "[BND]", "Version: " + std::to_string(int(version)));
    if (log)
        logger(0x20, "[BND]", "Info offset at: 0x" + to_hstring(p_info));
    if (log)
        logger(0x20, "[BND]", "File offset at: 0x" + to_hstring(p_file));

    for (int i = 0; i < p_entries; ++i) {
        //std::cout << std::hex << p_info+offset << " " << p_file << std::dec << endl;
        //logger(0x20, "[BND]", "Reading entry "+to_string(i+1)+"/"+to_string(p_entries));

        File temp;

        uint32_t p_crc = Binary::get_uint32(data, p_info + offset + 3);

        if (p_crc != 0x0) {
            std::vector<unsigned char> crc_block = Binary::get_block(data, p_crc, 0x10);
            uint32_t f_pointer = Binary::get_uint32(crc_block, 0x8);
            uint32_t f_size = Binary::get_uint32(crc_block, 0xC);

            //logger(0x20, "[BND]", "F_pointer: 0x"+to_hstring(f_pointer)+" F_size: 0x"+to_hstring(f_size));

            if (f_size >= 0x20000000)
                f_size -= 0x20000000;

            temp.level = int8_t(static_cast<unsigned char>(Binary::get_uint8(data, p_info + offset)));

            if (f_pointer < data.size())
                temp.data = Binary::get_block(data, f_pointer, f_size);

            temp.name = Binary::get_string(data, p_info + offset + 7);

            temp.dbg_data_offset = f_pointer;

            files.push_back(temp);

            offset += 7 + temp.name.size() + 1;
        }
    }

    if (log)
        logger(0x20, "[BND]", "File loaded successfully.");

    //  Insert the code that will be timed

    auto t_end = std::chrono::steady_clock::now();

    // Store the time difference between start and end
    auto diff = t_end - t_start;

    float diff_sec = std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
    if (log)
        logger(0x20, "[BND]", "Time taken: " + std::to_string(diff_sec / float(1000)) + " seconds");

    return true;
}

uint32_t BND::count_files() { // shouldn't this thing be O(1)?
    uint32_t f = 0;

    for (unsigned int i = 0; i < files.size(); ++i) {
        if (files[i].level < 0)
            ++f;
    }

    return f;
}

uint32_t BND::count_entries() { // shouldn't this thing be O(1)?
    return files.size() + empty_blocks;
}

std::string BND::get_full_name(int id) { // id is the index in "files" where an object is stored

    // target == 0 <=> files[id].level == +-1 

    // If we're asked for a directory with level == 2 (target == 1), then
    // we look for directories with level == 1.
    // When we find the closest one to files[id] from the left, we push its name to folders.
    // This continues until the last dir is processed, after which (??) we break.

    // TO DO: store an array parent_dir: parent_dir[id] == id of its parent directory ...
    // ... or -1 if it is located at root, I guess

    std::vector<std::string> folders;

    int target = std::abs(int(files[id].level)) - 1; // target >= 0

    for (int i = id; i >= 0; --i) {
        if (int(files[i].level) == target) { // this can only happen for directory objects
            folders.push_back(files[i].name);
            --target;
        }

        if (target <= 0) // if (target == 0 || target == -1)
            break;
    }

    std::string name = "";

    for (int i = folders.size() - 1; i >= 0; --i)
        name += folders[i];

    name += files[id].name;

    return name;
}

void BND::replace_file(int id, const std::string& path) {
    logger(0x20, "[BND]", "Replacing file " + files[id].name + " with " + path);
    files[id].data = Binary::file_to_uchar(Binary::get_file(path));
    logger(0x20, "[BND]", "File replaced successfully.");
}

int BND::get_type(int id) { // should be renamed to "is_directory"
    if (files[id].name[files[id].name.size() - 1] == '/') // if the last symbol of files[id].name is '/', it's a directory
        return 1;
    else
        return 0;
    // replace with ternary operator?
}

void BND::list_all_files() {
    for (int i = 0; i < files.size(); ++i) {
        std::cout << "ID " << i << ": " << get_full_name(i) << ", size: " << files[i].data.size() << ", level: " << int(files[i].level) << std::endl;
    }
}

// Fill the zipped vector with pairs consisting of the
// corresponding elements of a and b. (This assumes
// that the vectors have equal length)
template <typename A, typename B>
void zip(
    const std::vector<A> &a,
    const std::vector<B> &b,
    std::vector<std::pair<A, B>> &zipped) {
    for (size_t i = 0; i < a.size(); ++i) {
        zipped.push_back(std::make_pair(a[i], b[i]));
    }
}

// Write the first and second element of the pairs in
// the given zipped vector into a and b. (This assumes
// that the vectors have equal length)
template <typename A, typename B>
void unzip(
    const std::vector<std::pair<A, B>> &zipped,
    std::vector<A> &a,
    std::vector<B> &b) {
    for (size_t i = 0; i < a.size(); ++i) {
        a[i] = zipped[i].first;
        b[i] = zipped[i].second;
    }
}

void BND::list_sorted_via_offset() {
    std::vector<std::string> names;
    std::vector<uint32_t> score;

    for (int i = 0; i < files.size(); ++i) { // this part here is awful
        names.push_back(get_full_name(i));
        score.push_back(files[i].dbg_data_offset);
    }
    // TO DO: rewrite get_full_name(id) and think if this part can be improved

    // Zip the vectors together
    std::vector<std::pair<std::string, uint32_t>> zipped;
    zip(names, score, zipped);

    // Sort the vector of pairs
    std::sort(std::begin(zipped), std::end(zipped),
        [&](const auto& a, const auto& b) { return a.second < b.second;} ); // is it OK to capture everything by reference?

    // Write the sorted pairs back to the original vectors
    unzip(zipped, names, score);

    for (size_t i = 0; i < names.size(); ++i) {
        if (names[i][names[i].size() - 1] != '/') // if names[i] does not correspond to a directorys
            std::cout << names[i] << " : 0x" << std::hex << score[i] << std::dec << std::endl;
    }
}

void BND::extract(int id, std::string destination) {
    if (destination == "") {
        // This whole part is incredible! TO DO: bring <filesystem> here and rewrite all these path manipulations
        ///strip the dir
        std::string name = get_full_name(id);
        // example: 
        std::string a = original_name.substr(0, original_name.find_last_of("\\/") + 1);
        std::string b = original_name.substr(original_name.find_last_of("\\/") + 1);
        // example:

        std::string folder = a + "@" + b + "/" + name.substr(0, name.find_last_of("/") + 1);

        std::string cmd = "md \"" + folder + "\" >nul 1>nul 2>nul";
        for (int i = 0; i < cmd.size(); i++) {
            if (cmd[i] == '/')
                cmd[i] = '\\';
        }

        system(cmd.c_str());

        logger(0x20, "[BND]", "Extracting file " + files[id].name + " to " + a + "@" + b + "\\" + name);

        std::ofstream file(a + "@" + b + "\\" + name, std::ios::binary);
        file << Binary::uchar_to_file(files[id].data);
        file.close();
    }
    else {
        logger(0x20, "[BND]", "Extracting file " + files[id].name + " to " + destination);

        std::ofstream file(destination, std::ios::binary);
        file << Binary::uchar_to_file(files[id].data);
        file.close();
    }
}

/*void BND::extract_gzip(std::string name) {
    ///strip the dir
    std::string name = get_full_name(id);
    std::string a = original_name.substr(0,original_name.find_last_of("\\/")+1);
    std::string b = original_name.substr(original_name.find_last_of("\\/")+1);

    std::string folder = a+"@"+b+"/"+name.substr(0,name.find_last_of("/")+1);

    std::string cmd = "md "+folder+" >nul 1>nul 2>nul";
    for(int i=0; i<cmd.size(); ++i) {
        if(cmd[i] == '/')
        cmd[i] = '\\';
    }

    system(cmd.c_str());

    std::string szip = "7z.exe e "+a+"@"+b+"\\"+name+" -o "+folder+" -y";
    std::cout << szip << endl;

    system(szip.c_str());

    //std::ofstream file(a+"@"+b+"\\"+name, ios::binary);
    //file << Binary::uchar_to_file(files[id].data);
    //file.close();
}*/

void BND::extract_all() {
    for (unsigned int i = 0; i < files.size(); ++i) {
        extract(i);
    }
}

void BND::extract_literally_everything_dont_use_ever(BND bnd_handle) {
    for (unsigned int i = 0; i < bnd_handle.files.size(); ++i) {
        BND file;
        bnd_handle.extract(i);

        std::string a = bnd_handle.original_name.substr(0, bnd_handle.original_name.find_last_of("\\/") + 1);
        std::string b = bnd_handle.original_name.substr(bnd_handle.original_name.find_last_of("\\/") + 1);

        std::string name = a + "@" + b + "/" + bnd_handle.get_full_name(i);

        std::cout << name << std::endl;

        if (name[name.size() - 1] != '/') {
            //std::cout << "Extracting " << name << endl;
            file.load(name);
            file.extract_literally_everything_dont_use_ever(file);
        }
    }
}

void BND::remove_file(int id) {
    logger(0x20, "[BND]", "Removing entry " + files[id].name);

    if (files[id].level > 0) { ///folder

        int8_t target_level = (files[id].level + 1) * (-1);
        files.erase(files.begin() + id); ///remove the folder

        while (id < files.size()) { ///check if we can go further and start removing files
            ///yes
            if (files[id].level <= target_level || files[id].level >= (target_level * (-1))) {
                remove_file(id);
            }
            else {
                break; ///stop execution
            }
        }

    }
    else { ///negative => file
        files.erase(files.begin() + id);
    }
}


void BND::add_file(int id, const std::string& path, bool folder) { // why don't we have a id-less version of this function?
    logger(0x20, "[BND]", "Adding file " + path);

    int target = -1;

    for (int i = id - 1; i >= 0; --i) {
        //std::cout << "Looking for folder, ID " << i << ", level: " << int(files[i].level) << endl;

        if (int(files[i].level) > 0) {
            target = (int(files[i].level) + 1)*(-1);
            break;
        }
    }

    std::string name = path;

    if (!folder)
        name = path.substr(path.find_last_of("\\/") + 1);

    ///convert to lowercase
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });

    ///if added entry is a folder, swap the target folder_level to non_negative
    if (folder)
        target = std::abs(target);

    File temp;
    temp.level = target;

    ///if added entry is a folder, there's no need to put any data.
    if (folder)
        temp.data = {};
    else
        temp.data = Binary::file_to_uchar(Binary::get_file(path));
    // Shouldn't this part be moved to the start of the function?\
    // It would be quite troublesome if there's no file to begin with

    temp.name = name;

    //std::cout << "Adding " << name << " after id " << id << ", level: " << target << ", data size: " << temp.data.size() << " bytes" << endl;

    files.insert(files.begin() + id, temp);
}

void BND::save(const std::string& path) {
    logger(0x20, "[BND]", "Saving file to " + path);
    std::ofstream out(path, std::ios::binary);

    logger(0x20, "[BND]", "Building dictionary...");

    ///BND header
    uint32_t u32_header = 0x00444E42;
    uint32_t u32_version = version;
    uint32_t u32_zero = 0x0;
    uint32_t u32_info = empty_blocks * 0x10 + files.size() * 0x10 + 0x28;

    uint32_t u32_data = u32_info + files.size() * 0x7;

    for (unsigned int i = 0; i < files.size(); ++i)
        u32_data += files[i].name.size() + 0x1;

    uint32_t u32_data_prev = u32_data;

    while (u32_data % 512 != 0)
        u32_data += 0x1;

    uint32_t u32_data_zeroes = u32_data - u32_data_prev;

    uint32_t u32_files = count_files();
    uint32_t u32_entries = count_entries();

    out.write(reinterpret_cast<char*> (&u32_header), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_version), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));

    out.write(reinterpret_cast<char*> (&u32_info), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_data), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));

    out.write(reinterpret_cast<char*> (&u32_files), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_entries), sizeof(uint32_t));

    for (int i = 0; i < empty_blocks; ++i) {
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    }

    struct CRC_File {
        int id;
        uint32_t crc;
        uint32_t p_info;
        uint32_t p_data;
        uint32_t d_size;
    };

    struct Info_File {
        int id;
        int8_t folder_lvl;
        int8_t prev_entry;
        int8_t cur_entry;
        uint32_t p_crc;
        std::string name;
    };

    std::vector<CRC_File> crc_entries;
    std::vector<Info_File> info_entries;

    uint32_t file_offset = u32_data;
    uint32_t info_offset = u32_info;
    int8_t folder_lvl = -1;
    int8_t prev_len = -1;

    logger(0x20, "[BND]", "Creating CRC entries...");

    for (unsigned int i = 0; i < files.size(); ++i) {
        ///create a CRC entry
        CRC_File t_crc;
        Info_File t_info;
        t_crc.id = i;
        t_crc.crc = CRC::Calculate(get_full_name(i).c_str(), get_full_name(i).size(), CRC::CRC_32());
        t_crc.p_info = info_offset;
        t_crc.p_data = file_offset;
        t_crc.d_size = files[i].data.size();

        info_offset += 0x8 + files[i].name.size();
        file_offset += files[i].data.size();

        while ((file_offset % 2048) != 0) {
            file_offset++;
        }

        t_info.id = i;
        t_info.folder_lvl = files[i].level;
        t_info.prev_entry = prev_len;
        t_info.cur_entry = 0x8 + files[i].name.size();

        if (i == files.size() - 1)
            t_info.cur_entry = -1;

        t_info.p_crc = 0x0;
        t_info.name = files[i].name;

        crc_entries.push_back(t_crc);
        info_entries.push_back(t_info);
    }

    std::sort(crc_entries.begin(), crc_entries.end(), [](auto const &a, auto const &b) { return a.crc < b.crc; });

    for (unsigned int i = 0; i < info_entries.size(); ++i) {
        for (unsigned int a = 0; a < crc_entries.size(); ++a) {
            if (crc_entries[a].id == info_entries[i].id) {
                info_entries[i].p_crc = 0x28 + (empty_blocks * 0x10) + (a * 0x10);
            }
        }
    }

    logger(0x20, "[BND]", "Saving CRC entries...");

    for (unsigned int i = 0; i < crc_entries.size(); ++i) {
        out.write(reinterpret_cast<char*> (&crc_entries[i].crc), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].p_info), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].p_data), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].d_size), sizeof(uint32_t));
    }

    for (unsigned int i = 0; i < info_entries.size(); ++i) {
        out.write(reinterpret_cast<char*> (&info_entries[i].folder_lvl), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].prev_entry), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].cur_entry), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].p_crc), sizeof(uint32_t));
        out << info_entries[i].name;
        out.put(0x0);
    }

    for (int i = 0; i < u32_data_zeroes; ++i)
        out.put(0x0);

    logger(0x20, "[BND]", "Adding contents...");

    for (int i = 0; i < files.size(); ++i) {
        out << Binary::uchar_to_file(files[i].data);
        int a = files[i].data.size();

        while ((a % 2048) != 0) {
            out.put(0x0);
            ++a;
        }
    }

    out.close();

    logger(0x20, "[BND]", "Done. File saved at " + path);
}

void BND::save(const std::string& dict, const std::string& data) {
    logger(0x20, "[BND]", "Saving file to " + dict + " and " + data);
    std::ofstream out(dict, std::ios::binary);

    logger(0x20, "[BND]", "Building dictionary...");
    ///BND header
    uint32_t u32_header = 0x00444E42;
    uint32_t u32_version = version;
    uint32_t u32_zero = 0x0;
    uint32_t u32_info = empty_blocks * 0x10 + files.size() * 0x10 + 0x28;

    uint32_t u32_data = u32_info + files.size() * 0x7;

    for (unsigned int i = 0; i < files.size(); ++i)
        u32_data += files[i].name.size() + 0x1;

    uint32_t u32_data_prev = u32_data;

    while (u32_data % 512 != 0)
        u32_data += 0x1;

    uint32_t u32_data_zeroes = u32_data - u32_data_prev;

    uint32_t u32_files = count_files();
    uint32_t u32_entries = count_entries();

    out.write(reinterpret_cast<char*> (&u32_header), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_version), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));

    out.write(reinterpret_cast<char*> (&u32_info), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_data), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));

    out.write(reinterpret_cast<char*> (&u32_files), sizeof(uint32_t));
    out.write(reinterpret_cast<char*> (&u32_entries), sizeof(uint32_t));

    for (int i = 0; i < empty_blocks; ++i) {
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&u32_zero), sizeof(uint32_t));
    }

    struct CRC_File {
        int id;
        uint32_t crc;
        uint32_t p_info;
        uint32_t p_data;
        uint32_t d_size;
    };

    struct Info_File {
        int id;
        int8_t folder_lvl;
        int8_t prev_entry;
        int8_t cur_entry;
        uint32_t p_crc;
        std::string name;
    };

    std::vector<CRC_File> crc_entries;
    std::vector<Info_File> info_entries;

    uint32_t file_offset = u32_data;
    uint32_t info_offset = u32_info;
    int8_t folder_lvl = -1;
    int8_t prev_len = -1;

    file_offset = 0x0;
    logger(0x20, "[BND]", "Creating CRC entries...");

    for (unsigned int i = 0; i < files.size(); ++i) {
        //std::cout << "Creating new entry @ 0x" << hex << file_offset << dec << endl;

        ///create a CRC entry
        CRC_File t_crc;
        Info_File t_info;
        t_crc.id = i;
        t_crc.crc = CRC::Calculate(get_full_name(i).c_str(), get_full_name(i).size(), CRC::CRC_32());
        t_crc.p_info = info_offset;
        t_crc.p_data = file_offset;
        t_crc.d_size = files[i].data.size() + 0x20000000; ///weird af requirement

        info_offset += 0x8 + files[i].name.size();
        file_offset += files[i].data.size();

        while ((file_offset % 2048) != 0) {
            file_offset++;
        }

        t_info.id = i;
        t_info.folder_lvl = files[i].level;
        t_info.prev_entry = prev_len;
        t_info.cur_entry = 0x8 + files[i].name.size();

        if (i == files.size() - 1)
            t_info.cur_entry = -1;

        t_info.p_crc = 0x0;
        t_info.name = files[i].name;

        crc_entries.push_back(t_crc);
        info_entries.push_back(t_info);
    }

    std::sort(crc_entries.begin(), crc_entries.end(), [](auto const &a, auto const &b) { return a.crc < b.crc; });

    for (unsigned int i = 0; i < info_entries.size(); ++i) {
        for (unsigned int a = 0; a < crc_entries.size(); ++a) {
            if (crc_entries[a].id == info_entries[i].id) {
                info_entries[i].p_crc = 0x28 + (empty_blocks * 0x10) + (a * 0x10);
            }
        }
    }

    logger(0x20, "[BND]", "Saving CRC entries...");

    for (unsigned int i = 0; i < crc_entries.size(); ++i) {
        out.write(reinterpret_cast<char*> (&crc_entries[i].crc), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].p_info), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].p_data), sizeof(uint32_t));
        out.write(reinterpret_cast<char*> (&crc_entries[i].d_size), sizeof(uint32_t));
    }

    for (unsigned int i = 0; i < info_entries.size(); ++i) {
        out.write(reinterpret_cast<char*> (&info_entries[i].folder_lvl), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].prev_entry), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].cur_entry), sizeof(int8_t));
        out.write(reinterpret_cast<char*> (&info_entries[i].p_crc), sizeof(uint32_t));
        out << info_entries[i].name;
        out.put(0x0);
    }

    for (int i = 0; i < u32_data_zeroes; ++i)
        out.put(0x0);

    out.close();

    std::ofstream out2(data, std::ios::binary);
    out2.seekp(0);

    if (encrypt)
        logger(0x90, "[P3Hash]", "Encrypting the data file...");

    for (int i = 0; i < files.size(); ++i) {
        std::vector<unsigned char> file_to_save = files[i].data;

        if (encrypt) {
            std::vector<unsigned char> decrypted;

            for (int i = 0; i < file_to_save.size(); i += 16) {
                uint32_t a = Binary::get_uint32(file_to_save, i);
                uint32_t b = Binary::get_uint32(file_to_save, i + 4);
                uint32_t c = Binary::get_uint32(file_to_save, i + 8);
                uint32_t d = Binary::get_uint32(file_to_save, i + 12);

                std::vector<uint32_t> v_block = { a,b,c,d };

                libP3Hash handle;
                v_block = handle.encryptBlock(v_block);

                decrypted.push_back((v_block[0] >> 24) & 0xff);
                decrypted.push_back((v_block[0] >> 16) & 0xff);
                decrypted.push_back((v_block[0] >> 8) & 0xff);
                decrypted.push_back(v_block[0] & 0xff);

                decrypted.push_back((v_block[1] >> 24) & 0xff);
                decrypted.push_back((v_block[1] >> 16) & 0xff);
                decrypted.push_back((v_block[1] >> 8) & 0xff);
                decrypted.push_back(v_block[1] & 0xff);

                decrypted.push_back((v_block[2] >> 24) & 0xff);
                decrypted.push_back((v_block[2] >> 16) & 0xff);
                decrypted.push_back((v_block[2] >> 8) & 0xff);
                decrypted.push_back(v_block[2] & 0xff);

                decrypted.push_back((v_block[3] >> 24) & 0xff);
                decrypted.push_back((v_block[3] >> 16) & 0xff);
                decrypted.push_back((v_block[3] >> 8) & 0xff);
                decrypted.push_back(v_block[3] & 0xff);
            }

            file_to_save = decrypted;
        }

        out2 << Binary::uchar_to_file(file_to_save);
        int a = file_to_save.size();

        while ((a % 2048) != 0) {
            out2.put(0x0);
            ++a;
        }
    }

    out2.close();

    logger(0x20, "[BND]", "Done. File saved at " + dict + " and " + data);
}
