```python
import requests
import hashlib
import numpy as np

# Padding function
def padding(input_bytes):
    padding_len = 64 - (len(input_bytes) + 8) % 64
    padding_string = b'\x80' + b'\x00' * (padding_len - 1)
    input_bytes += padding_string
    input_bytes += len(input_bytes) * 8
    return input_bytes

# SHA-256 transformation function
def sha256_transform(message):
    message_words = [message[i:i + 32] for i in range(0, len(message), 32)]
    for i in range(16, 64):
        w1 = int.from_bytes(message_words[i - 15].encode(), byteorder='big')
        w2 = int.from_bytes(message_words[i - 2].encode(), byteorder='big')
        s0 = (w1 >> 7 | w1 << 25) ^ (w1 >> 18 | w1 << 14) ^ (w1 >> 3)
        s1 = (w2 >> 17 | w2 << 15) ^ (w2 >> 19 | w2 << 13) ^ (w2 >> 10)
        message_words.append(format((int(message_words[i - 16], 2) + s0 + int(message_words[i - 7], 2) + s1) % (2 ** 32), '032b'))
    return ''.join(message_words)

# SHA-256 compression function
def sha256_compression_function(block_of_16_words, h):
    k = [
        '428a2f98', '71374491', 'b5c0fbcf', 'e9b5dba5',
        '3956c25b', '59f111f1', '923f82a4', 'ab1c5ed5',
        'd807aa98', '12835b01', '243185be', '550c7dc3',
        '72be5d74', '80deb1fe', '9bdc06a7', 'c19bf174',
        'e49b69c1', 'efbe4786', '0fc19dc6', '240ca1cc',
        '2de92c6f', '4a7484aa', '5cb0a9dc', '76f988da',
        '983e5152', 'a831c66d', 'b00327c8', 'bf597fc7',
        'c6e00bf3', 'd5a79147', '06ca6351', '14292967',
        '27b70a85', '2e1b2138', '4d2c6dfc', '53380d13',
        '650a7354', '766a0abb', '81c2c92e', '92722c85',
        'a2bfe8a1', 'a81a664b', 'c24b8b70', 'c76c51a3',
        'd192e819', 'd6990624', 'f40e3585', '106aa070',
        '19a4c116', '1e376c08', '2748774c', '34b0bcb5',
        '391c0cb3', '4ed8aa4a', '5b9cca4f', '682e6ff3',
        '748f82ee', '78a5636f', '84c87814', '8cc70208',
        '90befffa', 'a4506ceb', 'bef9a3f7', 'c67178f2'
    ]

    a, b, c, d, e, f, g, h = [int(h[i:i + 8], 16) for i in range(0, len(h), 8)]
    w = [int(block_of_16_words[i:i + 32], 2) for i in range(16)]

    for i in range(64):
        s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)
        ch = (e & f) ^ (~e & g)
        temp1 = h + s1 + ch + int(k[i], 16) + w[i]
        s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = s0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2

    h0 = (a + int(h0, 16)) % (2 ** 32)
    h1 = (b + int(h1, 16)) % (2 ** 32)
    h2 = (c + int(h2, 16)) % (2 ** 32)
    h3 = (d + int(h3, 16)) % (2 ** 32)
    h4 = (e + int(h4, 16)) % (2 ** 32)
    h5 = (f + int(h5, 16)) % (2 ** 32)
    h6 = (g + int(h6, 16)) % (2 ** 32)
    h7 = (h + int(h7, 16)) % (2 ** 32)

    return format(h0, '08x') + format(h1, '08x') + format(h2, '08x') + format(h3, '08x') + \
           format(h4, '08x') + format(h5, '08x') + format(h6, '08x') + format(h7, '08x')

# Downloading the book of Mark
url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892"
response = requests.get(url)
mark_book = response.text

# Converting the text to bytes and applying padding
mark_book_bytes = mark_book.encode('utf-8')
mark_book_padded = padding(mark_book_bytes)

# Splitting the text into 512-bit blocks and applying SHA-256 transformation
h0, h1, h2, h3, h4, h5, h6, h7 = [
    '6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a',
    '510e527f', '9b05688c', '1f83d9ab', '5be0cd19'
]

for i in range(0
