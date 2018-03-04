// Using NTLM algorithm from:
// http://davenport.sourceforge.net/ntlm.html#theLmResponse
//
#include <algorithm>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

//---------------------------------------------------------------------------
//
void LM_Response(
		const char* password,
		const unsigned char* challenge, size_t challengesz,
		unsigned char* response, size_t responsesz);

std::ostream& log(const char* name, const unsigned char* buf, size_t bufsz);

void set_password(const char* in, unsigned char* out, size_t outsz);
void set_password(const std::string& in, unsigned char* out, size_t outsz);

bool des_create1(const unsigned char* part, size_t partsz, unsigned char* out, size_t outsz);
bool des_create(const unsigned char* part, size_t partsz, unsigned char* out, size_t outsz);

void save(const unsigned char* buf, size_t bufsz, const char* filename);
void save(const unsigned char* buf, size_t bufsz, const std::string& filename);

void des_encrypt(
		const unsigned char* plain, size_t plainsz, 
		const unsigned char* key,   size_t keysz, 
		      unsigned char* out,   size_t outsz);

//---------------------------------------------------------------------------
//
int main(int argc, char* argv[])
{
	const char* password = (argc == 1) ? "secret01" : (const char*)argv[1];
	const unsigned char challenge[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	unsigned char response[3 * 8] = {};
	LM_Response(password, challenge, sizeof(challenge), response, sizeof(response));
}

//---------------------------------------------------------------------------
//
void LM_Response(
		const char* password,
		const unsigned char* challenge, size_t challengesz,
		unsigned char* response, size_t responsesz)
{
	assert(password);
	assert(challenge);	assert(challengesz == 8);
	assert(response);	assert(responsesz == 3*8);

	// 1. The user's password (as an OEM string) is converted to uppercase.
	// 2. This password is null-padded to 14 bytes.
	// 3. This "fixed" password is split into two 7-byte halves.
	unsigned char passwd[2 * 7];
	set_password(password, passwd, sizeof(passwd));
	log("passwd", passwd, sizeof(passwd)) << std::endl;

	// 4. These values are used to create two DES keys (one from each 7-byte half).
	unsigned char destwo8[2 * 8] = {};
	des_create(passwd, 7,     destwo8,     8);
	des_create(passwd + 7, 7, destwo8 + 8, 8);
	log("destwo8 1", destwo8, 8);
	log("destwo8 2", destwo8 + 8, 8) << std::endl;

	// 5. Each of these keys is used to DES-encrypt the constant ASCII string "KGS!@#$%" (resulting in two 8-byte ciphertext values).
	// 6. These two ciphertext values are concatenated to form a 16-byte value - the LM hash.
	// 7. The 16-byte LM hash is null-padded to 21 bytes.
	// 8. This value is split into three 7-byte thirds.
	// 9. These values are used to create three DES keys (one from each 7-byte third).
	const unsigned char key[] = { 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
	log("key", key, sizeof(key)) << std::endl;

	unsigned char desthree7[21] = {};
	des_encrypt(key, 8, destwo8,     8, desthree7,     8);
	des_encrypt(key, 8, destwo8 + 8, 8, desthree7 + 8, 8);
	log("desthree7 1", desthree7 + 0*7, 7);
	log("desthree7 2", desthree7 + 1*7, 7);
	log("desthree7 3", desthree7 + 2*7, 7) << std::endl;

	unsigned char desthree8[3 * 8] = {};
	des_create(desthree7 + 0*7, 7, desthree8 + 0*8, 8);
	des_create(desthree7 + 1*7, 7, desthree8 + 1*8, 8);
	des_create(desthree7 + 2*7, 7, desthree8 + 2*8, 8);
	log("desthree8 1", desthree8 + 0*8, 8);
	log("desthree8 2", desthree8 + 1*8, 8);
	log("desthree8 3", desthree8 + 2*8, 8) << std::endl;

	// 10. Each of these keys is used to DES-encrypt the challenge from the Type 2 message (resulting in three 8-byte ciphertext values).
	// 11. These three ciphertext values are concatenated to form a 24-byte value. This is the LM response.
	des_encrypt(challenge, challengesz, desthree8 + 0*8, 8, response + 0*8, 8);
	des_encrypt(challenge, challengesz, desthree8 + 1*8, 8, response + 1*8, 8);
	des_encrypt(challenge, challengesz, desthree8 + 2*8, 8, response + 2*8, 8);
	log("challenge", challenge, 8) << std::endl;
	log("response 1", response + 0*8, 8);
	log("response 2", response + 1*8, 8);
	log("response 3", response + 2*8, 8) << std::endl;
}

//---------------------------------------------------------------------------
//
std::ostream& log(const char* name, const unsigned char* buf, size_t bufsz)
{
	std::cout << std::setfill(' ') << std::left << std::setw(11) << name << " = { ";
	for (size_t i = 0; i != bufsz; ++i)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)buf[i] << " ";
	return std::cout << "}\n";
}

//---------------------------------------------------------------------------
//
void set_password(const char* in, unsigned char* out, size_t outsz)
{
	memset(out, 0, outsz);
	for (size_t i = 0; i != outsz && in[i]; ++i)
		out[i] = toupper(in[i]);
}

void set_password(const std::string& in, unsigned char* out, size_t outsz)
{
	set_password(in.c_str(), out, outsz);
}

//---------------------------------------------------------------------------
// unused
bool des_create1(const unsigned char* part, size_t partsz, unsigned char* out, size_t outsz)
{
	//	for each byte
	//		for each bit
	//			append 1 if bit set
	//			append 0 if bit clear
	//			count++
	//			append zero if (count % 7 == 0)

	if (partsz != 7 || outsz != 8)
		return false;

	std::string key;
	int count = 0;
	for (int i = 0; i < 7*8; i += 8) {
		for (int pos = 7; pos >= 0; --pos) {
			unsigned char newval = (part[i/8] >> pos) & 0x01;
			const char* bit = newval ? "1" : "0";
			key.push_back(bit[0]);

			++count;
			if ((count % 7) == 0) {
				key.push_back("0"[0]);
			}
		}
	}

	for (size_t i = 0; i != key.size(); i += 8) {
		std::string val = key.substr(i, 8);
		int count = 0;
		for (size_t i = 0; i != val.size(); ++i)
			if (val[i] == '1')
				++count;

		if ((count % 2) == 0)
			key[i + 7] = '1';
	}

	memset(out, 0, outsz);
	for (size_t i = 0; i != key.size(); i += 8) {
		for (int pos = 0; pos < 8; ++pos) {
			out[i/8] <<= 1;
			if (key[i + pos] == '1')
				out[i/8] |= 0x01;
		}
	}

	return true;
}

//---------------------------------------------------------------------------
//
namespace
{
	std::vector<bool> to_vec(const unsigned char* in, size_t insz)
	{
		std::vector<bool> vec;

		for (size_t i = 0; i < insz; ++i) {
			unsigned char byte = in[i];
			for (int bit = 0; bit < 8; ++bit) {
				vec.push_back(static_cast<signed char>(byte) < 0);
				byte <<= 1;
			}
		}

		return vec;
	}

	void from_vec(const std::vector<bool>& vec, unsigned char* out, size_t outsz)
	{
		memset(out, 0, outsz);

		for (size_t i = 0, mx = std::min(vec.size()/8, outsz); i < mx; ++i) {
			unsigned char& byte = out[i];

			for (int bit = 0; bit < 8; ++bit) {
				byte <<= 1;
				byte |= vec[8*i + bit] ? 1 : 0;
			}
		}
	}

	enum parity_t { odd, even };

	std::vector<bool> set_parity(const std::vector<bool>& vec, parity_t parity = even)
	{
		std::vector<bool> out;

		const size_t bytesz = 7;
		for (size_t i = 0; bytesz*i < vec.size(); ++i) {
			int count = 0;
			for (size_t j = 0; j < bytesz; ++j) {
				out.push_back(vec[bytesz*i + j]);
				if (vec[bytesz*i + j]) ++count;
			}

			out.push_back((count%2 != 0) == parity);
		}

		return out;
	}
}

bool des_create(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz)
{
	//	for each byte
	//		for each bit
	//			append 1 if bit set
	//			append 0 if bit clear
	//			count++
	//			append zero if (count % 7 == 0)

	if (!in || !out || (insz != 7) || (outsz != 8))
		return false;

	std::vector<bool> key = to_vec(in, insz);
	key = set_parity(key, odd);
	from_vec(key, out, outsz);

	return true;
}

//---------------------------------------------------------------------------
//
void save(const unsigned char* buf, size_t bufsz, const char* filename)
{
	std::ofstream f(filename, std::ios::binary | std::ios::trunc);
	f.write((const char*)buf, bufsz);
}

void save(const unsigned char* buf, size_t bufsz, const std::string& filename)
{
	save(buf, bufsz, filename.c_str());
}

//---------------------------------------------------------------------------
//
namespace
{
	extern "C"
	{
		// https://github.com/tarequeh/DES.git
		//
		#define ENCRYPTION_MODE 1
		#define DECRYPTION_MODE 0

		typedef struct {
			unsigned char k[8];
			unsigned char c[4];
			unsigned char d[4];
		} key_set;

		void generate_key(unsigned char* key);
		void generate_sub_keys(const unsigned char* main_key, key_set* key_sets);
		void process_message(const unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode);

		int initial_key_permutaion[] = {57, 49,  41, 33,  25,  17,  9,
										 1, 58,  50, 42,  34,  26, 18,
										10,  2,  59, 51,  43,  35, 27,
										19, 11,   3, 60,  52,  44, 36,
										63, 55,  47, 39,  31,  23, 15,
										 7, 62,  54, 46,  38,  30, 22,
										14,  6,  61, 53,  45,  37, 29,
										21, 13,   5, 28,  20,  12,  4};

		int initial_message_permutation[] =	   {58, 50, 42, 34, 26, 18, 10, 2,
												60, 52, 44, 36, 28, 20, 12, 4,
												62, 54, 46, 38, 30, 22, 14, 6,
												64, 56, 48, 40, 32, 24, 16, 8,
												57, 49, 41, 33, 25, 17,  9, 1,
												59, 51, 43, 35, 27, 19, 11, 3,
												61, 53, 45, 37, 29, 21, 13, 5,
												63, 55, 47, 39, 31, 23, 15, 7};

		int key_shift_sizes[] = {-1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

		int sub_key_permutation[] =    {14, 17, 11, 24,  1,  5,
										 3, 28, 15,  6, 21, 10,
										23, 19, 12,  4, 26,  8,
										16,  7, 27, 20, 13,  2,
										41, 52, 31, 37, 47, 55,
										30, 40, 51, 45, 33, 48,
										44, 49, 39, 56, 34, 53,
										46, 42, 50, 36, 29, 32};

		int message_expansion[] =  {32,  1,  2,  3,  4,  5,
									 4,  5,  6,  7,  8,  9,
									 8,  9, 10, 11, 12, 13,
									12, 13, 14, 15, 16, 17,
									16, 17, 18, 19, 20, 21,
									20, 21, 22, 23, 24, 25,
									24, 25, 26, 27, 28, 29,
									28, 29, 30, 31, 32,  1};

		int S1[] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
					 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
					 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
					15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13};

		int S2[] = {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
					 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
					 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
					13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9};

		int S3[] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
					13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
					13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
					 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

		int S4[] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
					13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
					10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
					 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

		int S5[] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
					14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
					 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
					11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

		int S6[] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
					10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
					 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
					 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

		int S7[] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
					13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
					 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
					 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};

		int S8[] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
					 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
					 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
					 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};

		int right_sub_message_permutation[] =    {16,  7, 20, 21,
											29, 12, 28, 17,
											 1, 15, 23, 26,
											 5, 18, 31, 10,
											 2,  8, 24, 14,
											32, 27,  3,  9,
											19, 13, 30,  6,
											22, 11,  4, 25};

		int final_message_permutation[] =  {40,  8, 48, 16, 56, 24, 64, 32,
											39,  7, 47, 15, 55, 23, 63, 31,
											38,  6, 46, 14, 54, 22, 62, 30,
											37,  5, 45, 13, 53, 21, 61, 29,
											36,  4, 44, 12, 52, 20, 60, 28,
											35,  3, 43, 11, 51, 19, 59, 27,
											34,  2, 42, 10, 50, 18, 58, 26,
											33,  1, 41,  9, 49, 17, 57, 25};


		void print_char_as_binary(char input) {
			int i;
			for (i=0; i<8; i++) {
				char shift_byte = 0x01 << (7-i);
				if (shift_byte & input) {
					printf("1");
				} else {
					printf("0");
				}
			}
		}

		void generate_key(unsigned char* key) {
			int i;
			for (i=0; i<8; i++) {
				key[i] = rand()%255;
			}
		}

		void print_key_set(key_set key_set){
			int i;
			printf("K: \n");
			for (i=0; i<8; i++) {
				printf("%02X : ", key_set.k[i]);
				print_char_as_binary(key_set.k[i]);
				printf("\n");
			}
			printf("\nC: \n");

			for (i=0; i<4; i++) {
				printf("%02X : ", key_set.c[i]);
				print_char_as_binary(key_set.c[i]);
				printf("\n");
			}
			printf("\nD: \n");

			for (i=0; i<4; i++) {
				printf("%02X : ", key_set.d[i]);
				print_char_as_binary(key_set.d[i]);
				printf("\n");
			}
			printf("\n");
		}

		void generate_sub_keys(const unsigned char* main_key, key_set* key_sets) {
			int i, j;
			int shift_size;
			unsigned char shift_byte, first_shift_bits, second_shift_bits, third_shift_bits, fourth_shift_bits;

			for (i=0; i<8; i++) {
				key_sets[0].k[i] = 0;
			}

			for (i=0; i<56; i++) {
				shift_size = initial_key_permutaion[i];
				shift_byte = 0x80 >> ((shift_size - 1)%8);
				shift_byte &= main_key[(shift_size - 1)/8];
				shift_byte <<= ((shift_size - 1)%8);

				key_sets[0].k[i/8] |= (shift_byte >> i%8);
			}

			for (i=0; i<3; i++) {
				key_sets[0].c[i] = key_sets[0].k[i];
			}

			key_sets[0].c[3] = key_sets[0].k[3] & 0xF0;

			for (i=0; i<3; i++) {
				key_sets[0].d[i] = (key_sets[0].k[i+3] & 0x0F) << 4;
				key_sets[0].d[i] |= (key_sets[0].k[i+4] & 0xF0) >> 4;
			}

			key_sets[0].d[3] = (key_sets[0].k[6] & 0x0F) << 4;


			for (i=1; i<17; i++) {
				for (j=0; j<4; j++) {
					key_sets[i].c[j] = key_sets[i-1].c[j];
					key_sets[i].d[j] = key_sets[i-1].d[j];
				}

				shift_size = key_shift_sizes[i];
				if (shift_size == 1){
					shift_byte = 0x80;
				} else {
					shift_byte = 0xC0;
				}

				// Process C
				first_shift_bits = shift_byte & key_sets[i].c[0];
				second_shift_bits = shift_byte & key_sets[i].c[1];
				third_shift_bits = shift_byte & key_sets[i].c[2];
				fourth_shift_bits = shift_byte & key_sets[i].c[3];

				key_sets[i].c[0] <<= shift_size;
				key_sets[i].c[0] |= (second_shift_bits >> (8 - shift_size));

				key_sets[i].c[1] <<= shift_size;
				key_sets[i].c[1] |= (third_shift_bits >> (8 - shift_size));

				key_sets[i].c[2] <<= shift_size;
				key_sets[i].c[2] |= (fourth_shift_bits >> (8 - shift_size));

				key_sets[i].c[3] <<= shift_size;
				key_sets[i].c[3] |= (first_shift_bits >> (4 - shift_size));

				// Process D
				first_shift_bits = shift_byte & key_sets[i].d[0];
				second_shift_bits = shift_byte & key_sets[i].d[1];
				third_shift_bits = shift_byte & key_sets[i].d[2];
				fourth_shift_bits = shift_byte & key_sets[i].d[3];

				key_sets[i].d[0] <<= shift_size;
				key_sets[i].d[0] |= (second_shift_bits >> (8 - shift_size));

				key_sets[i].d[1] <<= shift_size;
				key_sets[i].d[1] |= (third_shift_bits >> (8 - shift_size));

				key_sets[i].d[2] <<= shift_size;
				key_sets[i].d[2] |= (fourth_shift_bits >> (8 - shift_size));

				key_sets[i].d[3] <<= shift_size;
				key_sets[i].d[3] |= (first_shift_bits >> (4 - shift_size));

				for (j=0; j<48; j++) {
					shift_size = sub_key_permutation[j];
					if (shift_size <= 28) {
						shift_byte = 0x80 >> ((shift_size - 1)%8);
						shift_byte &= key_sets[i].c[(shift_size - 1)/8];
						shift_byte <<= ((shift_size - 1)%8);
					} else {
						shift_byte = 0x80 >> ((shift_size - 29)%8);
						shift_byte &= key_sets[i].d[(shift_size - 29)/8];
						shift_byte <<= ((shift_size - 29)%8);
					}

					key_sets[i].k[j/8] |= (shift_byte >> j%8);
				}
			}
		}

		void process_message(const unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode) {
			int i, k;
			int shift_size;
			unsigned char shift_byte;

			unsigned char initial_permutation[8];
			memset(initial_permutation, 0, 8);
			memset(processed_piece, 0, 8);

			for (i=0; i<64; i++) {
				shift_size = initial_message_permutation[i];
				shift_byte = 0x80 >> ((shift_size - 1)%8);
				shift_byte &= message_piece[(shift_size - 1)/8];
				shift_byte <<= ((shift_size - 1)%8);

				initial_permutation[i/8] |= (shift_byte >> i%8);
			}

			unsigned char l[4], r[4];
			for (i=0; i<4; i++) {
				l[i] = initial_permutation[i];
				r[i] = initial_permutation[i+4];
			}

			unsigned char ln[4], rn[4], er[6], ser[4];

			int key_index;
			for (k=1; k<=16; k++) {
				memcpy(ln, r, 4);

				memset(er, 0, 6);

				for (i=0; i<48; i++) {
					shift_size = message_expansion[i];
					shift_byte = 0x80 >> ((shift_size - 1)%8);
					shift_byte &= r[(shift_size - 1)/8];
					shift_byte <<= ((shift_size - 1)%8);

					er[i/8] |= (shift_byte >> i%8);
				}

				if (mode == DECRYPTION_MODE) {
					key_index = 17 - k;
				} else {
					key_index = k;
				}

				for (i=0; i<6; i++) {
					er[i] ^= key_sets[key_index].k[i];
				}

				unsigned char row, column;

				for (i=0; i<4; i++) {
					ser[i] = 0;
				}

				// 0000 0000 0000 0000 0000 0000
				// rccc crrc cccr rccc crrc cccr

				// Byte 1
				row = 0;
				row |= ((er[0] & 0x80) >> 6);
				row |= ((er[0] & 0x04) >> 2);

				column = 0;
				column |= ((er[0] & 0x78) >> 3);

				ser[0] |= ((unsigned char)S1[row*16+column] << 4);

				row = 0;
				row |= (er[0] & 0x02);
				row |= ((er[1] & 0x10) >> 4);

				column = 0;
				column |= ((er[0] & 0x01) << 3);
				column |= ((er[1] & 0xE0) >> 5);

				ser[0] |= (unsigned char)S2[row*16+column];

				// Byte 2
				row = 0;
				row |= ((er[1] & 0x08) >> 2);
				row |= ((er[2] & 0x40) >> 6);

				column = 0;
				column |= ((er[1] & 0x07) << 1);
				column |= ((er[2] & 0x80) >> 7);

				ser[1] |= ((unsigned char)S3[row*16+column] << 4);

				row = 0;
				row |= ((er[2] & 0x20) >> 4);
				row |= (er[2] & 0x01);

				column = 0;
				column |= ((er[2] & 0x1E) >> 1);

				ser[1] |= (unsigned char)S4[row*16+column];

				// Byte 3
				row = 0;
				row |= ((er[3] & 0x80) >> 6);
				row |= ((er[3] & 0x04) >> 2);

				column = 0;
				column |= ((er[3] & 0x78) >> 3);

				ser[2] |= ((unsigned char)S5[row*16+column] << 4);

				row = 0;
				row |= (er[3] & 0x02);
				row |= ((er[4] & 0x10) >> 4);

				column = 0;
				column |= ((er[3] & 0x01) << 3);
				column |= ((er[4] & 0xE0) >> 5);

				ser[2] |= (unsigned char)S6[row*16+column];

				// Byte 4
				row = 0;
				row |= ((er[4] & 0x08) >> 2);
				row |= ((er[5] & 0x40) >> 6);

				column = 0;
				column |= ((er[4] & 0x07) << 1);
				column |= ((er[5] & 0x80) >> 7);

				ser[3] |= ((unsigned char)S7[row*16+column] << 4);

				row = 0;
				row |= ((er[5] & 0x20) >> 4);
				row |= (er[5] & 0x01);

				column = 0;
				column |= ((er[5] & 0x1E) >> 1);

				ser[3] |= (unsigned char)S8[row*16+column];

				for (i=0; i<4; i++) {
					rn[i] = 0;
				}

				for (i=0; i<32; i++) {
					shift_size = right_sub_message_permutation[i];
					shift_byte = 0x80 >> ((shift_size - 1)%8);
					shift_byte &= ser[(shift_size - 1)/8];
					shift_byte <<= ((shift_size - 1)%8);

					rn[i/8] |= (shift_byte >> i%8);
				}

				for (i=0; i<4; i++) {
					rn[i] ^= l[i];
				}

				for (i=0; i<4; i++) {
					l[i] = ln[i];
					r[i] = rn[i];
				}
			}

			unsigned char pre_end_permutation[8];
			for (i=0; i<4; i++) {
				pre_end_permutation[i] = r[i];
				pre_end_permutation[4+i] = l[i];
			}

			for (i=0; i<64; i++) {
				shift_size = final_message_permutation[i];
				shift_byte = 0x80 >> ((shift_size - 1)%8);
				shift_byte &= pre_end_permutation[(shift_size - 1)/8];
				shift_byte <<= ((shift_size - 1)%8);

				processed_piece[i/8] |= (shift_byte >> i%8);
			}
		}
	}
}

void des_encrypt(
		const unsigned char* plain, size_t plainsz, 
		const unsigned char* key,   size_t keysz, 
		      unsigned char* out,   size_t outsz)
{
	assert(plain);	assert(plainsz == 8);
	assert(key);	assert(keysz == 8);
	assert(out);	assert(outsz == 8);

	key_set key_sets[17];
	generate_sub_keys(key, key_sets);
	process_message(plain, out, key_sets, ENCRYPTION_MODE);
}
