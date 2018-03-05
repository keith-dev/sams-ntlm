// Using NTLM algorithm from:
// http://davenport.sourceforge.net/ntlm.html#theLmResponse

#include <openssl/des.h>
//
#include <algorithm>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

//#include <ctype.h>
//#include <string.h>
//#include <stdio.h>
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
void des_encrypt(
		const unsigned char* plain, size_t plainsz, 
		const unsigned char* key,   size_t keysz, 
		      unsigned char* out,   size_t outsz)
{
	assert(plain);	assert(plainsz == 8);
	assert(key);	assert(keysz == 8);
	assert(out);	assert(outsz == 8);

	DES_key_schedule keysched;
	DES_set_key((C_Block *)key, &keysched);
	DES_ecb_encrypt((C_Block *)plain, (C_Block *)out, &keysched, DES_ENCRYPT);
}
