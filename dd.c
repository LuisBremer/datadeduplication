#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>

/****************************** MACROS ******************************/
// Definiciones de macros para rotaciones y operaciones bit a bit utilizadas en SHA-256
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
// Definiciones de tipos para bytes y palabras de 32 bits
typedef uint8_t BYTE; // Byte de 8 bits
typedef uint32_t WORD; // Palabra de 32 bits

// Estructura de contexto para SHA-256
typedef struct {
	BYTE data[64]; // Bloque de datos de 512 bits (64 bytes)
	WORD datalen; // Longitud de los datos
	unsigned long long bitlen; // Longitud de los datos en bits
	WORD state[8]; // Estado interno del hash
} SHA256_CTX;

// Constantes para SHA-256 (raíz cúbica de los primeros 64 números primos fraccionados)
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
// Función para transformar el estado del hash con un bloque de datos
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]) {
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	// Extender los primeros 16 bloques en 64 bloques
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	// Inicializar variables de trabajo con el estado actual del contexto
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	// Realizar 64 rondas de compresión
	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	// Sumar las variables de trabajo al estado del contexto
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

// Función para inicializar el contexto de SHA-256
void sha256_init(SHA256_CTX *ctx) {
	ctx->datalen = 0; // Longitud inicial de los datos es 0
	ctx->bitlen = 0; // Longitud inicial en bits es 0
	// Valores iniciales del estado (hash inicial)
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

// Función para actualizar el contexto con datos nuevos
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len) {
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) { // Si el bloque está lleno, transformarlo
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512; // Incrementar la longitud de bits
			ctx->datalen = 0; // Reiniciar la longitud de datos
		}
	}
}

// Función para finalizar el hash y obtener el resultado
void sha256_final(SHA256_CTX *ctx, BYTE hash[]) {
	WORD i = ctx->datalen;

	// Padding: agregar un bit '1' seguido de ceros
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Agregar la longitud total del mensaje en bits y transformar
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

	// Dado que esta implementación usa el orden de bytes little endian y SHA usa big endian,
	// revertir todos los bytes al copiar el estado final al hash de salida.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

/*************************** FUNCIONES ADICIONALES ***************************/

// Estructura de diccionario para almacenar hashes y rutas de archivos
typedef struct FileNode {
    char *file_path;
    struct FileNode *next;
} FileNode;

typedef struct {
    BYTE hash[32];
    FileNode *files;
} HashEntry;

#define MAX_FILES 10000 // Número máximo de archivos
HashEntry hash_table[MAX_FILES];
int hash_count = 0;

// Función para comparar dos hashes
bool compare_hashes(BYTE hash1[32], BYTE hash2[32]) {
    return memcmp(hash1, hash2, 32) == 0;
}

// Función para agregar un archivo a la tabla de hashes
void add_to_hash_table(BYTE hash[32], const char *file_path) {
    for (int i = 0; i < hash_count; i++) {
        if (compare_hashes(hash_table[i].hash, hash)) {
            FileNode *new_node = malloc(sizeof(FileNode));
            new_node->file_path = strdup(file_path);
            new_node->next = hash_table[i].files;
            hash_table[i].files = new_node;
            return;
        }
    }

    // Si el hash no existe, añadir una nueva entrada
    memcpy(hash_table[hash_count].hash, hash, 32);
    hash_table[hash_count].files = malloc(sizeof(FileNode));
    hash_table[hash_count].files->file_path = strdup(file_path);
    hash_table[hash_count].files->next = NULL;
    hash_count++;
}

// Función para calcular el hash de un archivo
void hash_file(const char *file_path, BYTE hash[32]) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        return;
    }

    SHA256_CTX ctx;
    BYTE data[1024];
    size_t bytesRead;

    sha256_init(&ctx);
    while ((bytesRead = fread(data, 1, sizeof(data), file)) > 0) {
        sha256_update(&ctx, data, bytesRead);
    }
    sha256_final(&ctx, hash);

    fclose(file);
}

// Función para escanear un directorio y calcular los hashes de los archivos
void scan_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;
    char path[1024];

    if (!dir) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {  // Si es un archivo regular
            snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

            // Filtrar archivos no deseados como .DS_Store
            if (strcmp(entry->d_name, ".DS_Store") == 0) {
                continue;
            }

            BYTE hash[32];
            // Calcular el hash del archivo
            hash_file(path, hash);

            // Agregar el archivo a la tabla de hashes
            add_to_hash_table(hash, path);
        } else if (entry->d_type == DT_DIR) {  // Si es un directorio
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
                // Escanear el subdirectorio recursivamente
                scan_directory(path);
            }
        }
    }
    closedir(dir);
}

// Función para imprimir los archivos duplicados
void print_duplicates() {
    for (int i = 0; i < hash_count; i++) {
        FileNode *node = hash_table[i].files;
        if (node && node->next) {  // Solo imprimir si hay más de un archivo
            printf("Archivos duplicados:\n");
            while (node) {
                printf("%s\n", node->file_path);
                node = node->next;
            }
            printf("\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <directorio>\n", argv[0]);
        return 1;
    }

    // Escanear el directorio
    scan_directory(argv[1]);

    // Imprimir archivos duplicados
    print_duplicates();

    // Liberar memoria utilizada para almacenar las rutas de los archivos
    for (int i = 0; i < hash_count; i++) {
        FileNode *node = hash_table[i].files;
        while (node) {
            FileNode *next = node->next;
            free(node->file_path);
            free(node);
            node = next;
        }
    }

    return 0;
}