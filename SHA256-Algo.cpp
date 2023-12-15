#include <iostream>
#include <iomanip>
#include <vector>
#include <sstream>
#include <bitset>
#include <cstdint>
#include <algorithm>
#include <cmath>

std::string padding(const std::string &input_bytes) {
    size_t padding_len = 64 - (input_bytes.length() + 8) % 64;
    std::string padding_string(1, '\x80');
    padding_string += std::string(padding_len - 1, '\x00');
    input_bytes += padding_string;

    uint64_t length = input_bytes.length() * 8;
    for (int i = 7; i >= 0; --i) {
        input_bytes += static_cast<char>((length >> (i * 8)) & 0xFF);
    }
    return input_bytes;
}

std::string sha256_transform(const std::string &message) {
    std::vector<std::string> message_words;
    for (size_t i = 0; i < message.length(); i += 32) {
        message_words.push_back(message.substr(i, 32));
    }

    for (size_t i = 16; i < 64; ++i) {
        uint32_t w1 = std::bitset<32>(message_words[i - 15]).to_ulong();
        uint32_t w2 = std::bitset<32>(message_words[i - 2]).to_ulong();
        uint32_t s0 = (w1 >> 7 | w1 << 25) ^ (w1 >> 18 | w1 << 14) ^ (w1 >> 3);
        uint32_t s1 = (w2 >> 17 | w2 << 15) ^ (w2 >> 19 | w2 << 13) ^ (w2 >> 10);
        message_words.push_back(std::bitset<32>((std::bitset<32>(message_words[i - 16]).to_ulong() + s0 +
                                                 std::bitset<32>(message_words[i - 7]).to_ulong() + s1) %
                                                static_cast<uint32_t>(pow(2, 32))).to_string());
    }
    std::string result;
    for (const auto &word : message_words) {
        result += word;
    }
    return result;
}

std::string sha256_compression_function(const std::string &block_of_16_words, uint32_t &h0, uint32_t &h1, uint32_t &h2,
                                        uint32_t &h3, uint32_t &h4, uint32_t &h5, uint32_t &h6, uint32_t &h7) {
    std::vector<std::string> k = {
        "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5",
        "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
        "d807aa98", "12835b01", "243185be", "550c7dc3",
        "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
        "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc",
        "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
        "983e5152", "a831c66d", "b00327c8", "bf597fc7",
        "c6e00bf3", "d5a79147", "06ca6351", "14292967",
        "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13",
        "650a7354", "766a0abb", "81c2c92e", "92722c85",
        "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3",
        "d192e819", "d6990624", "f40e3585", "106aa070",
        "19a4c116", "1e376c08", "2748774c", "34b0bcb5",
        "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
        "748f82ee", "78a5636f", "84c87814", "8cc70208",
        "90befffa", "a4506ceb", "bef9a3f7", "c67178f2"
    };

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    std::vector<uint32_t> w;
    for (size_t i = 0; i < block_of_16_words.length(); i += 32) {
        w.push_back(std::bitset<32>(block_of_16_words.substr(i, 32)).to_ulong());
    }

    for (size_t i = 0; i < 64; ++i) {
        uint32_t s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + std::stoul(k[i], nullptr, 16) + w[i];
        uint32_t s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h0 = (a + h0) % static_cast<uint32_t>(pow(2, 32));
    h1 = (b + h1) % static_cast<uint32_t>(pow(2, 32));
    h2 = (c + h2) % static_cast<uint32_t>(pow(2, 32));
    h3 = (d + h3) % static_cast<uint32_t>(pow(2, 32));
    h4 = (e + h4) % static_cast<uint32_t>(pow(2, 32));
    h5 = (f + h5) % static_cast<uint32_t>(pow(2, 32));
    h6 = (g + h6) % static_cast<uint32_t>(pow(2, 32));
    h7 = (h + h7) % static_cast<uint32_t>(pow(2, 32));

    std::stringstream result;
    result << std::setfill('0') << std::setw(8) << std::hex << h0
           << std::setfill('0') << std::setw(8) << std::hex << h1
           << std::setfill('0') << std::setw(8) << std::hex << h2
           << std::setfill('0') << std::setw(8) << std::hex << h3
           << std::setfill('0') << std::setw(8) << std::hex << h4
           << std::setfill('0') << std::setw(8) << std::hex << h5
           << std::setfill('0') << std::setw(8) << std::hex << h6
           << std::setfill('0') << std::setw(8) << std::hex << h7;

    return result.str();
}

int main() {
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    // Assume you have a way to fetch the content from the URL and store it in the variable 'mark_book'
    std::string mark_book = "content_from_the_url";
    
    // Converting the text to bytes and applying padding
    std::string mark_book_bytes = padding(mark_book);
    
    // Splitting the text into 512-bit blocks and applying SHA-256 transformation
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
             h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    for (size_t i = 0; i < mark_book_bytes.length(); i += 64) {
        std::string block = mark_book_bytes.substr(i, 64);
        std::string block_words;
        for (size_t j = 0; j < block.length(); j += 32) {
            block_words += block.substr(j, 32);
        }

        // Apply SHA-256 compression function
        std::string result = sha256_compression_function(sha256_transform(block_words), h0, h1, h2, h3, h4, h5, h6, h7);

        // Update hash values
        std::stringstream ss(result);
        ss >> std::hex >> h0 >> h1 >> h2 >> h3 >> h4 >> h5 >> h6 >> h7;
    }

    // Final hash value
    std::cout << "Final SHA-256 Hash: "
              << std::setfill('0') << std::setw(8) << std::hex << h0
              << std::setfill('0') << std::setw(8) << std::hex << h1
              << std::setfill('0') << std::setw(8) << std::hex << h2
              << std::setfill('0') << std::setw(8) << std::hex << h3
              << std::setfill('0') << std::setw(8) << std::hex << h4
              << std::setfill('0') << std::setw(8) << std::hex << h5
              << std::setfill('0') << std::setw(8) << std::hex << h6
              << std::setfill('0') << std::setw(8) << std::hex << h7 << std::endl;

    return 0;
}
