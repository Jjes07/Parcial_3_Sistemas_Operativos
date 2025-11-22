/* GSEA.cpp - VERSIÓN COMPLETA CON OPERACIONES COMBINADAS
*
* Herramienta para comprimir y descomprimir archivos usando LZW
* Herramienta para encriptar y desencriptar archivos usando ChaCha20
* con llamadas POSIX directas (open/read/write/close, opendir/readdir).
*
* NUEVO: Soporta operaciones combinadas -ce (comprimir+encriptar) y -du (desencriptar+descomprimir)
*
* Uso:
* ./gsea -c --comp-alg lzw -i <ruta_entrada> -o <ruta_salida>
* ./gsea -d --comp-alg lzw -i <ruta_entrada> -o <ruta_salida>
* ./gsea -e --enc-alg chacha20 -i <ruta_entrada> -o <ruta_salida> -k <clave>
* ./gsea -u --enc-alg chacha20 -i <ruta_entrada> -o <ruta_salida> -k <clave>
* ./gsea -ce --comp-alg lzw --enc-alg chacha20 -i <ruta_entrada> -o <ruta_salida> -k <clave>
* ./gsea -du --comp-alg lzw --enc-alg chacha20 -i <ruta_entrada> -o <ruta_salida> -k <clave>
*/

#define _GNU_SOURCE
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>
#include <sstream>
#include <sys/types.h>
#include <stdint.h>

using namespace std;

// =====================================
//  HELPERS GENERALES
// =====================================

static off_t file_size(const string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
        return st.st_size;
    return -1;
}

static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t*)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= w;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t*)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0)
            return 1; // EOF prematuro
        p += r;
        n -= r;
    }
    return 0;
}

static int read_entire_file(const char *path, uint8_t **outbuf, size_t *outlen) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    off_t sz = file_size(path);
    if (sz < 0) { close(fd); return -1; }

    uint8_t *buf = (uint8_t*)malloc(sz);
    if (!buf) { close(fd); return -1; }

    if (read_all(fd, buf, sz) != 0) {
        close(fd);
        free(buf);
        return -1;
    }
    close(fd);
    *outbuf = buf;
    *outlen = sz;
    return 0;
}

// =====================================
//  NUEVAS FUNCIONES PARA ARCHIVOS TEMPORALES
// =====================================

static string generate_temp_filename() {
    char temp_template[] = "/tmp/gsea_XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd < 0) {
        return string("/tmp/gsea_temp_") + to_string(getpid()) + "_" + to_string(time(NULL));
    }
    close(fd);
    return string(temp_template);
}

static void cleanup_temp_file(const string &path) {
    if (!path.empty() && path.find("/tmp/gsea_") != string::npos) {
        unlink(path.c_str());
    }
}

// =====================================
//  LZW - CONSTANTES
// =====================================

static const int LZW_MAX_DICT = 4096;

// =====================================
//  LZW - COMPRESIÓN
// =====================================

int compress_buffer_lzw(const uint8_t *input, size_t length, int outfd) {
    struct Entry {
        vector<uint8_t> seq;
    };

    vector<Entry> dict;
    dict.reserve(LZW_MAX_DICT);

    for (int i = 0; i < 256; i++) {
        Entry e;
        e.seq.push_back((uint8_t)i);
        dict.push_back(e);
    }

    vector<uint8_t> cur;
    cur.reserve(32);

    auto dict_find = [&](const vector<uint8_t> &seq)->int {
        for (int i = 0; i < (int)dict.size(); i++) {
            const auto &d = dict[i].seq;
            if (d.size() == seq.size() && memcmp(d.data(), seq.data(), seq.size()) == 0) {
                return i;
            }
        }
        return -1;
    };

    auto write_code = [&](uint16_t code) {
        uint8_t b[2];
        b[0] = code & 0xFF;
        b[1] = (code >> 8) & 0xFF;
        write_all(outfd, b, 2);
    };

    for (size_t i = 0; i < length; i++) {
        uint8_t c = input[i];

        vector<uint8_t> test = cur;
        test.push_back(c);

        int idx = dict_find(test);
        if (idx >= 0) {
            cur.push_back(c);
        } else {
            int prev_idx = dict_find(cur);
            write_code((uint16_t)prev_idx);

            if (dict.size() < LZW_MAX_DICT) {
                Entry e;
                e.seq = test;
                dict.push_back(e);
            }
            cur.clear();
            cur.push_back(c);
        }
    }

    if (!cur.empty()) {
        int idx = dict_find(cur);
        write_code((uint16_t)idx);
    }

    return 0;
}

// =====================================
//  LZW - DESCOMPRESIÓN
// =====================================

static int decompress_fd_lzw(int in_fd, int out_fd) {

    auto read_code = [&](uint16_t *out)->int {
        uint8_t b[2];
        int r = read_all(in_fd, b, 2);
        if (r != 0) return 0;
        *out = (uint16_t)(b[0] | (b[1] << 8));
        return 1;
    };

    struct Entry {
        vector<uint8_t> seq;
    };

    vector<Entry> dict;
    dict.reserve(LZW_MAX_DICT);

    for (int i = 0; i < 256; i++) {
        Entry e;
        e.seq.push_back((uint8_t)i);
        dict.push_back(e);
    }

    uint16_t prev_code;
    if (!read_code(&prev_code)) return 0;

    vector<uint8_t> out = dict[prev_code].seq;
    write_all(out_fd, out.data(), out.size());

    uint16_t code;
    while (read_code(&code)) {
        vector<uint8_t> seq;
        if (code < dict.size()) {
            seq = dict[code].seq;
        } else {
            seq = dict[prev_code].seq;
            seq.push_back(dict[prev_code].seq[0]);
        }

        write_all(out_fd, seq.data(), seq.size());

        if (dict.size() < LZW_MAX_DICT) {
            vector<uint8_t> new_entry = dict[prev_code].seq;
            new_entry.push_back(seq[0]);
            dict.push_back({new_entry});
        }

        prev_code = code;
    }

    return 0;
}

// =====================================
//  SHA-256
// =====================================

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} SHA256_CTX;

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667u; ctx->state[1]=0xbb67ae85u;
    ctx->state[2]=0x3c6ef372u; ctx->state[3]=0xa54ff53au;
    ctx->state[4]=0x510e527fu; ctx->state[5]=0x9b05688cu;
    ctx->state[6]=0x1f83d9abu; ctx->state[7]=0x5be0cd19u;
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t m[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t)data[i*4] << 24 | (uint32_t)data[i*4+1] << 16 | (uint32_t)data[i*4+2] << 8 | (uint32_t)data[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(m[i-15],7) ^ rotr(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = rotr(m[i-2],17) ^ rotr(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K256[i] + m[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (int j = 0; j < 8; ++j) {
        hash[j*4]     = (ctx->state[j] >> 24) & 0xFF;
        hash[j*4 + 1] = (ctx->state[j] >> 16) & 0xFF;
        hash[j*4 + 2] = (ctx->state[j] >> 8) & 0xFF;
        hash[j*4 + 3] = (ctx->state[j]) & 0xFF;
    }
}

static void derive_key_from_passphrase(const char *passphrase, uint8_t key32[32]) {
    const char *DEFAULT_KEY = "GSEA-default-key-please-change!";
    SHA256_CTX ctx;
    sha256_init(&ctx);
    if (passphrase && passphrase[0] != '\0') {
        sha256_update(&ctx, (const uint8_t*)passphrase, strlen(passphrase));
    } else {
        sha256_update(&ctx, (const uint8_t*)DEFAULT_KEY, strlen(DEFAULT_KEY));
    }
    sha256_final(&ctx, key32);
}

// =====================================
//  ChaCha20
// =====================================

static inline uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void u32tole(uint8_t *p, uint32_t x) {
    p[0] = x & 0xFF; p[1] = (x>>8)&0xFF; p[2] = (x>>16)&0xFF; p[3] = (x>>24)&0xFF;
}

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    const uint32_t constants[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    uint32_t state[16];
    state[0] = constants[0]; state[1] = constants[1]; state[2] = constants[2]; state[3] = constants[3];
    for (int i = 0; i < 8; ++i) state[4+i] = u32le(&key[i*4]);
    state[12] = counter;
    state[13] = u32le(&nonce[0]);
    state[14] = u32le(&nonce[4]);
    state[15] = u32le(&nonce[8]);

    uint32_t working[16];
    memcpy(working, state, sizeof(state));

    auto quarter_round = [&](int a, int b, int c, int d) {
        working[a] += working[b]; working[d] ^= working[a]; working[d] = rotr(working[d], 16);
        working[c] += working[d]; working[b] ^= working[c]; working[b] = rotr(working[b], 12);
        working[a] += working[b]; working[d] ^= working[a]; working[d] = rotr(working[d], 8);
        working[c] += working[d]; working[b] ^= working[c]; working[b] = rotr(working[b], 7);
    };

    for (int i = 0; i < 10; ++i) {
        quarter_round(0,4,8,12);
        quarter_round(1,5,9,13);
        quarter_round(2,6,10,14);
        quarter_round(3,7,11,15);
        quarter_round(0,5,10,15);
        quarter_round(1,6,11,12);
        quarter_round(2,7,8,13);
        quarter_round(3,4,9,14);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t x = working[i] + state[i];
        u32tole(&out[i*4], x);
    }
}

static void chacha20_xor_keystream(const uint8_t key[32], const uint8_t nonce[12],
                                   uint64_t offset_blocks, uint8_t *dst, size_t len) {
    size_t pos = 0;
    uint32_t counter = (uint32_t)(offset_blocks & 0xFFFFFFFFu);
    while (pos < len) {
        uint8_t block[64];
        chacha20_block(key, nonce, counter, block);
        size_t take = (len - pos) < 64 ? (len - pos) : 64;
        for (size_t i = 0; i < take; ++i) dst[pos + i] ^= block[i];
        pos += take;
        counter++;
    }
}

typedef struct {
    uint8_t *buf;
    size_t offset;
    size_t len;
    const uint8_t *key;
    const uint8_t *nonce;
    uint64_t start_block;
} ChaChunkArg;

static void *chacha_chunk_worker(void *arg) {
    ChaChunkArg *a = (ChaChunkArg*)arg;
    chacha20_xor_keystream(a->key, a->nonce, a->start_block, a->buf + a->offset, a->len);
    return nullptr;
}

static int chacha20_xor_file_parallel(uint8_t *data, size_t data_len,
                                     const uint8_t key[32], const uint8_t nonce[12],
                                     int num_threads) {
    if (num_threads < 1) num_threads = 1;
    size_t chunk_base = data_len / (size_t)num_threads;
    size_t rem = data_len % (size_t)num_threads;
    pthread_t *threads = (pthread_t*)malloc(sizeof(pthread_t) * num_threads);
    ChaChunkArg *args = (ChaChunkArg*)malloc(sizeof(ChaChunkArg) * num_threads);
    if (!threads || !args) { free(threads); free(args); return -1; }

    size_t offset = 0;
    for (int i = 0; i < num_threads; ++i) {
        size_t this_len = chunk_base + (i < (int)rem ? 1 : 0);
        args[i].buf = data;
        args[i].offset = offset;
        args[i].len = this_len;
        args[i].key = key;
        args[i].nonce = nonce;
        args[i].start_block = (offset / 64);
        if (this_len > 0) {
            if (pthread_create(&threads[i], NULL, chacha_chunk_worker, &args[i]) != 0) {
                chacha_chunk_worker(&args[i]);
                threads[i] = 0;
            }
        } else {
            threads[i] = 0;
        }
        offset += this_len;
    }

    for (int i = 0; i < num_threads; ++i) {
        if (threads[i]) pthread_join(threads[i], NULL);
    }
    free(threads);
    free(args);
    return 0;
}

static int generate_random_nonce(uint8_t nonce[12]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, nonce, 12);
    close(fd);
    return (r == 12) ? 0 : -1;
}

static int chacha20_encrypt_file(const char *inpath, const char *outpath,
                                 const char *passphrase, int num_threads) {
    uint8_t key[32];
    derive_key_from_passphrase(passphrase, key);

    uint8_t *buf = nullptr;
    size_t buf_len = 0;
    if (read_entire_file(inpath, &buf, &buf_len) != 0) return -1;

    uint8_t nonce[12];
    if (generate_random_nonce(nonce) != 0) {
        memset(nonce, 0, 12);
    }

    if (chacha20_xor_file_parallel(buf, buf_len, key, nonce, num_threads) != 0) {
        free(buf); return -1;
    }

    int out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { free(buf); return -1; }

    if (write_all(out_fd, nonce, 12) != 0) { close(out_fd); free(buf); return -1; }
    if (buf_len > 0) {
        if (write_all(out_fd, buf, buf_len) != 0) { close(out_fd); free(buf); return -1; }
    }
    close(out_fd);
    free(buf);
    return 0;
}

static int chacha20_decrypt_file(const char *inpath, const char *outpath,
                                 const char *passphrase, int num_threads) {
    uint8_t key[32];
    derive_key_from_passphrase(passphrase, key);

    uint8_t *buf = nullptr;
    size_t total_len = 0;
    if (read_entire_file(inpath, &buf, &total_len) != 0) return -1;
    if (total_len < 12) { free(buf); return -1; }

    uint8_t nonce[12];
    memcpy(nonce, buf, 12);
    uint8_t *cipher = buf + 12;
    size_t cipher_len = total_len - 12;

    if (chacha20_xor_file_parallel(cipher, cipher_len, key, nonce, num_threads) != 0) {
        free(buf); return -1;
    }

    int out_fd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { free(buf); return -1; }
    if (cipher_len > 0) {
        if (write_all(out_fd, cipher, cipher_len) != 0) { close(out_fd); free(buf); return -1; }
    }
    close(out_fd);
    free(buf);
    return 0;
}

// =====================================
//  FILE JOB STRUCT
// =====================================

struct FileJob {
    string inpath;
    string outpath;
    int mode;          // 0=compress, 1=decompress, 2=encrypt, 3=decrypt, 4=-ce, 5=-du
    string pass;
    int num_threads;
    string comp_alg;
    string enc_alg;
};

// =====================================
//  Helpers para nombres
// =====================================

static string strip_extension(const string &name) {
    size_t pos = name.find_last_of('.');
    if (pos == string::npos) return name;
    return name.substr(0, pos);
}

static string get_extension(const string &name) {
    size_t pos = name.find_last_of('.');
    if (pos == string::npos) return "";
    return name.substr(pos);
}

static string basename_only(const string &path) {
    size_t pos = path.find_last_of('/');
    if (pos == string::npos) return path;
    return path.substr(pos + 1);
}

static bool file_exists(const string &path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static string increment_filename(const string &path) {
    string base = strip_extension(path);
    string ext = get_extension(path);

    int n = 1;
    while (true) {
        string candidate = base + "_" + to_string(n) + ext;
        if (!file_exists(candidate)) return candidate;
        n++;
    }
}

static string ask_overwrite_or_increment(const string &path) {
    if (!file_exists(path)) return path;

    cout << "\n El archivo '" << path << "' ya existe.\n";
    cout << "   [r] Reemplazar\n";
    cout << "   [n] Crear copia con contador\n";
    cout << "Elige opción: ";

    char op;
    cin >> op;
    if (op == 'r' || op == 'R') {
        unlink(path.c_str());
        return path;
    }
    return increment_filename(path);
}

// =====================================
//  FILE WORKER
// =====================================

static void* file_worker(void *arg) {
    FileJob *job = (FileJob*)arg;
    off_t before = file_size(job->inpath);
    uint8_t *buf = nullptr;
    size_t buf_len = 0;

    int in_fd = open(job->inpath.c_str(), O_RDONLY);
    if (in_fd < 0) {
        perror("Error abriendo archivo");
        delete job;
        return nullptr;
    }

    // =============================
    //     MODO COMPRESIÓN (-c)
    // =============================
    if (job->mode == 0) {
        if (read_entire_file(job->inpath.c_str(), &buf, &buf_len) != 0) {
            cerr << "Error leyendo archivo " << job->inpath << endl;
            close(in_fd);
            delete job;
            return nullptr;
        }

        string out = job->outpath + "/" + basename_only(job->inpath) + ".lzw";
        out = ask_overwrite_or_increment(out);

        int out_fd = open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            perror("Error escribiendo archivo");
            close(in_fd);
            free(buf);
            delete job;
            return nullptr;
        }

        uint64_t orig_size = buf_len;
        write_all(out_fd, &orig_size, sizeof(orig_size));
        compress_buffer_lzw(buf, buf_len, out_fd);

        close(out_fd);
        free(buf);

        off_t after = file_size(out);
        double ratio = (before > 0) ? (after * 100.0 / before) : 0;

        cout << "Archivo comprimido: " << out << endl;
        cout << "  Tamaño original: " << before << " bytes\n";
        cout << "  Comprimido:      " << after  << " bytes\n";
        cout << "  Ahorro:          " << (100.0 - ratio) << "%\n\n";

        close(in_fd);
        delete job;
        return nullptr;
    }

    // =============================
    //     MODO DESCOMPRESIÓN (-d)
    // =============================
    if (job->mode == 1) {
        uint64_t expected_size;
        if (read_all(in_fd, &expected_size, sizeof(expected_size)) != 0) {
            cerr << "Error leyendo encabezado LZW\n";
            close(in_fd);
            delete job;
            return nullptr;
        }

        string fname = basename_only(job->inpath);
        string base = strip_extension(strip_extension(fname));
        string ext  = get_extension(strip_extension(fname));
        if (ext == "") ext = ".out";

        string out = job->outpath + "/" + base + "-d" + ext;
        out = ask_overwrite_or_increment(out);

        int out_fd = open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            perror("Error creando archivo");
            close(in_fd);
            delete job;
            return nullptr;
        }

        decompress_fd_lzw(in_fd, out_fd);

        close(out_fd);
        close(in_fd);

        off_t after = file_size(out);
        double recovery = expected_size > 0 ? (after * 100.0 / expected_size) : 0;

        cout << "Archivo descomprimido: " << out << endl;
        cout << "  Tamaño comprimido:  " << before << " bytes\n";
        cout << "  Tamaño original:    " << expected_size << " bytes\n";
        cout << "  Recuperado:         " << after << " bytes\n";
        cout << "  Recuperación:       " << recovery << "%\n\n";

        delete job;
        return nullptr;
    }

    // =============================
    //     MODO ENCRIPTAR (-e)
    // =============================
    if (job->mode == 2) {
        string fname = basename_only(job->inpath);
        string out = job->outpath + "/" + fname + ".enc";
        out = ask_overwrite_or_increment(out);

        close(in_fd);

        if (chacha20_encrypt_file(job->inpath.c_str(), out.c_str(),
                                  job->pass.c_str(), job->num_threads) != 0) {
            cerr << "Error encriptando archivo\n";
        } else {
            cout << "Archivo encriptado: " << out << "\n";
        }

        delete job;
        return nullptr;
    }

    // =============================
    //     MODO DESENCRIPTAR (-u)
    // =============================
    if (job->mode == 3) {
        string fname = basename_only(job->inpath);
        string base = strip_extension(strip_extension(fname));
        string ext  = get_extension(strip_extension(fname));
        if (ext == "") ext = ".out";

        string out = job->outpath + "/" + base + "-u" + ext;
        out = ask_overwrite_or_increment(out);

        close(in_fd);

        if (chacha20_decrypt_file(job->inpath.c_str(), out.c_str(),
                                  job->pass.c_str(), job->num_threads) != 0) {
            cerr << "Error desencriptando archivo\n";
        } else {
            cout << "Archivo desencriptado: " << out << "\n";
        }

        delete job;
        return nullptr;
    }

    // =============================
    //  NUEVO: MODO -ce (COMPRIMIR + ENCRIPTAR)
    // =============================
    if (job->mode == 4) {
        cout << "\n=== Operación combinada: Compresión + Encriptación ===" << endl;
        cout << "Archivo: " << job->inpath << endl;

        // PASO 1: Comprimir a archivo temporal
        string temp_compressed = generate_temp_filename() + ".lzw";
        
        if (read_entire_file(job->inpath.c_str(), &buf, &buf_len) != 0) {
            cerr << "Error leyendo archivo " << job->inpath << endl;
            close(in_fd);
            delete job;
            return nullptr;
        }

        int temp_fd = open(temp_compressed.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (temp_fd < 0) {
            perror("Error creando archivo temporal");
            close(in_fd);
            free(buf);
            delete job;
            return nullptr;
        }

        uint64_t orig_size = buf_len;
        write_all(temp_fd, &orig_size, sizeof(orig_size));
        compress_buffer_lzw(buf, buf_len, temp_fd);
        close(temp_fd);
        free(buf);

        off_t compressed_size = file_size(temp_compressed);
        cout << "  [1/2] Compresión LZW completada" << endl;
        cout << "        Original: " << before << " bytes → Comprimido: " 
             << compressed_size << " bytes" << endl;

        // PASO 2: Encriptar archivo comprimido
        string fname = basename_only(job->inpath);
        string final_out = job->outpath + "/" + fname + ".lzw.enc";
        final_out = ask_overwrite_or_increment(final_out);

        if (chacha20_encrypt_file(temp_compressed.c_str(), final_out.c_str(),
                                  job->pass.c_str(), job->num_threads) != 0) {
            cerr << "Error encriptando archivo comprimido\n";
            cleanup_temp_file(temp_compressed);
            close(in_fd);
            delete job;
            return nullptr;
        }

        cleanup_temp_file(temp_compressed);

        off_t final_size = file_size(final_out);
        double total_ratio = (before > 0) ? (final_size * 100.0 / before) : 0;

        cout << "  [2/2] Encriptación ChaCha20 completada" << endl;
        cout << "\n✓ Resultado final: " << final_out << endl;
        cout << "  Tamaño original:     " << before << " bytes" << endl;
        cout << "  Tamaño final:        " << final_size << " bytes" << endl;
        cout << "  Ratio total:         " << total_ratio << "%" << endl;
        cout << "  Ahorro:              " << (100.0 - total_ratio) << "%\n" << endl;

        close(in_fd);
        delete job;
        return nullptr;
    }

    // =============================
    //  NUEVO: MODO -du (DESENCRIPTAR + DESCOMPRIMIR)
    // =============================
    if (job->mode == 5) {
        cout << "\n=== Operación combinada: Desencriptación + Descompresión ===" << endl;
        cout << "Archivo: " << job->inpath << endl;

        string temp_decrypted = generate_temp_filename() + ".lzw";

        close(in_fd);

        if (chacha20_decrypt_file(job->inpath.c_str(), temp_decrypted.c_str(),
                                  job->pass.c_str(), job->num_threads) != 0) {
            cerr << "Error desencriptando archivo\n";
            delete job;
            return nullptr;
        }

        off_t decrypted_size = file_size(temp_decrypted);
        cout << "  [1/2] Desencriptación ChaCha20 completada" << endl;
        cout << "        Encriptado: " << before << " bytes → Desencriptado: " 
             << decrypted_size << " bytes" << endl;

        int temp_fd = open(temp_decrypted.c_str(), O_RDONLY);
        if (temp_fd < 0) {
            perror("Error abriendo archivo temporal");
            cleanup_temp_file(temp_decrypted);
            delete job;
            return nullptr;
        }

        uint64_t expected_size;
        if (read_all(temp_fd, &expected_size, sizeof(expected_size)) != 0) {
            cerr << "Error leyendo encabezado LZW del archivo desencriptado\n";
            close(temp_fd);
            cleanup_temp_file(temp_decrypted);
            delete job;
            return nullptr;
        }

        string fname = basename_only(job->inpath);
        string base = strip_extension(strip_extension(strip_extension(fname)));
        string ext = get_extension(strip_extension(strip_extension(fname)));
        if (ext == "") ext = ".out";

        string final_out = job->outpath + "/" + base + "-du" + ext;
        final_out = ask_overwrite_or_increment(final_out);

        int out_fd = open(final_out.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            perror("Error creando archivo de salida");
            close(temp_fd);
            cleanup_temp_file(temp_decrypted);
            delete job;
            return nullptr;
        }

        decompress_fd_lzw(temp_fd, out_fd);
        close(temp_fd);
        close(out_fd);

        cleanup_temp_file(temp_decrypted);

        off_t final_size = file_size(final_out);
        double recovery = expected_size > 0 ? (final_size * 100.0 / expected_size) : 0;

        cout << "  [2/2] Descompresión LZW completada" << endl;
        cout << "\n✓ Resultado final: " << final_out << endl;
        cout << "  Tamaño encriptado:   " << before << " bytes" << endl;
        cout << "  Tamaño esperado:     " << expected_size << " bytes" << endl;
        cout << "  Tamaño recuperado:   " << final_size << " bytes" << endl;
        cout << "  Recuperación:        " << recovery << "%\n" << endl;

        delete job;
        return nullptr;
    }

    close(in_fd);
    delete job;
    return nullptr;
}

// =====================================
//  PROCESS DIRECTORY
// =====================================

static bool is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

static bool is_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    return S_ISREG(st.st_mode);
}

static int process_directory(const string &indir, const string &outdir,
                             int mode, const string &pass, int num_threads,
                             const string &comp_alg, const string &enc_alg)
{
    DIR *dp = opendir(indir.c_str());
    if (!dp) {
        perror("Error abriendo directorio");
        return -1;
    }

    struct dirent *ent;
    vector<pthread_t> threads;

    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        string full_in = indir + "/" + ent->d_name;

        if (!is_file(full_in.c_str()))
            continue;

        FileJob *job = new FileJob();
        job->inpath = full_in;
        job->outpath = outdir;
        job->mode = mode;
        job->pass = pass;
        job->num_threads = num_threads;
        job->comp_alg = comp_alg;
        job->enc_alg = enc_alg;

        pthread_t th;
        if (pthread_create(&th, NULL, file_worker, job) != 0) {
            file_worker(job);
        } else {
            threads.push_back(th);
        }
    }

    closedir(dp);

    for (pthread_t &t : threads)
        pthread_join(t, NULL);

    return 0;
}

// =====================================
//  PRINT HELP
// =====================================

static void print_help() {
    cout << "\nGSEA – Gestor Seguro de Encriptación y Archivo\n\n";
    cout << "Uso:\n";
    cout << "  ./gsea -c --comp-alg lzw -i <input> -o <output_dir>\n";
    cout << "  ./gsea -d --comp-alg lzw -i <input> -o <output_dir>\n";
    cout << "  ./gsea -e --enc-alg chacha20 -i <input> -o <output_dir> -k <clave>\n";
    cout << "  ./gsea -u --enc-alg chacha20 -i <input> -o <output_dir> -k <clave>\n";
    cout << "  ./gsea -ce --comp-alg lzw --enc-alg chacha20 -i <input> -o <output_dir> -k <clave>\n";
    cout << "  ./gsea -du --comp-alg lzw --enc-alg chacha20 -i <input> -o <output_dir> -k <clave>\n\n";
    cout << "Opciones:\n";
    cout << "  -c           Comprimir archivo (LZW)\n";
    cout << "  -d           Descomprimir archivo (LZW)\n";
    cout << "  -e           Encriptar archivo (ChaCha20)\n";
    cout << "  -u           Desencriptar archivo (ChaCha20)\n";
    cout << "  -ce          Comprimir + Encriptar (pipeline)\n";
    cout << "  -du          Desencriptar + Descomprimir (pipeline)\n";
    cout << "  --comp-alg   lzw (único disponible)\n";
    cout << "  --enc-alg    chacha20 (único disponible)\n";
    cout << "  -k           clave para cifrado/descifrado\n";
    cout << "  --threads N  número de hilos (por defecto = núcleos CPU)\n";
    cout << endl;
}

// =====================================
//  MAIN
// =====================================

int main(int argc, char **argv) {

    if (argc == 1) {
        print_help();
        return 0;
    }

    int mode = -1;  
    string comp_alg = "";
    string enc_alg = "";
    string k = "";
    string inpath = "";
    string outpath = "";
    int num_threads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads < 1) num_threads = 1;

    for (int i = 1; i < argc; i++) {
        string a = argv[i];

        if (a == "-c") mode = 0;
        else if (a == "-d") mode = 1;
        else if (a == "-e") mode = 2;
        else if (a == "-u") mode = 3;
        else if (a == "-ce") mode = 4;
        else if (a == "-du") mode = 5;
        else if (a == "--comp-alg") {
            if (i + 1 < argc) comp_alg = argv[++i];
        }
        else if (a == "--enc-alg") {
            if (i + 1 < argc) enc_alg = argv[++i];
        }
        else if (a == "-i") {
            if (i + 1 < argc) inpath = argv[++i];
        }
        else if (a == "-o") {
            if (i + 1 < argc) outpath = argv[++i];
        }
        else if (a == "-k") {
            if (i + 1 < argc) k = argv[++i];
        }
        else if (a == "--threads") {
            if (i + 1 < argc) num_threads = atoi(argv[++i]);
        }
        else {
            cout << "Argumento desconocido: " << a << endl;
            return 1;
        }
    }

    if (mode < 0) {
        cerr << "Error: No se especificó modo -c | -d | -e | -u | -ce | -du\n";
        return 1;
    }

    if (inpath == "") {
        cerr << "Error: Falta -i <input>\n";
        return 1;
    }

    if (outpath == "") {
        cerr << "Error: Falta -o <output>\n";
        return 1;
    }

    if ((mode == 0 || mode == 1 || mode == 4 || mode == 5) && comp_alg == "") {
        cerr << "Error: Falta --comp-alg para compresión/descompresión\n";
        return 1;
    }

    if ((mode == 0 || mode == 1 || mode == 4 || mode == 5) && comp_alg != "lzw") {
        cerr << "Error: --comp-alg debe ser lzw\n";
        return 1;
    }

    if ((mode == 2 || mode == 3 || mode == 4 || mode == 5) && enc_alg == "") {
        cerr << "Error: Falta --enc-alg para cifrado/descifrado\n";
        return 1;
    }

    if ((mode == 2 || mode == 3 || mode == 4 || mode == 5) && enc_alg != "chacha20") {
        cerr << "Error: --enc-alg debe ser chacha20\n";
        return 1;
    }

    if ((mode == 2 || mode == 3 || mode == 4 || mode == 5) && k == "") {
        cerr << "Advertencia: No se proporcionó clave (-k). Se usará clave por defecto.\n";
        cerr << "Para mayor seguridad, proporcione una clave con -k\n";
    }

    mkdir(outpath.c_str(), 0755);

    if (!is_directory(inpath.c_str()) && !is_file(inpath.c_str())) {
        cerr << "Error: Ruta de entrada inválida: " << inpath << endl;
        return 1;
    }

    if (is_file(inpath.c_str())) {
        FileJob *job = new FileJob();
        job->inpath = inpath;
        job->outpath = outpath;
        job->mode = mode;
        job->pass = k;
        job->num_threads = num_threads;
        job->comp_alg = comp_alg;
        job->enc_alg = enc_alg;

        file_worker(job);
    }
    else if (is_directory(inpath.c_str())) {
        process_directory(inpath, outpath, mode, k, num_threads, comp_alg, enc_alg);
    }

    return 0;
}