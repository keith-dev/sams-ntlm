#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>

#include <ctype.h>
#include <string.h>

void set_password(const char* in, unsigned char* out, size_t outsz);
void set_password(const std::string& in, unsigned char* out, size_t outsz);

bool des_create1(const unsigned char* part, size_t partsz, unsigned char* out, size_t outsz);
bool des_create2(const unsigned char* part, size_t partsz, unsigned char* out, size_t outsz);

int main(void)
{
	unsigned char passwd[2 * 7];
	set_password("secret01", passwd, 7);

	const unsigned char lmstr = { 0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };

	unsigned char out[2 * 8];
	bool ok;

	memset(out, 0, sizeof(out));
	ok = des_create1(passwd, 7, out, 8) && des_create1(passwd + 7, 7, out + 8, 8);
	std::cout << "des_create1() : " << (ok ? "true" : "false") << std::endl;
	if (ok) {
		std::cout << "pass = { ";
		for (size_t i = 0; i != sizeof(passwd); ++i)
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)passwd[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "key  = { ";
		for (size_t i = 0; i != sizeof(out); ++i)
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)out[i] << " ";
		std::cout << "}\n" << std::endl;
	}

	memset(out, 0, sizeof(out));
	ok = des_create2(passwd, 7, out, 8) && des_create2(passwd + 7, 7, out + 8, 8);
	std::cout << "des_create2() : " << (ok ? "true" : "false") << std::endl;
	if (ok) {
		std::cout << "pass = { ";
		for (size_t i = 0; i != sizeof(passwd); ++i)
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)passwd[i] << " ";
		std::cout << "}" << std::endl;
		std::cout << "key  = { ";
		for (size_t i = 0; i != sizeof(out); ++i)
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)out[i] << " ";
		std::cout << "}\n" << std::endl;
	}
}

void set_password(const char* in, unsigned char* out, size_t outsz)
{
	memset(out, 0, outsz);
	for (size_t i = 0, mx = std::min(outsz, strlen(in)); i != mx; ++i)
		out[i] = toupper(in[i]);
}

void set_password(const std::string& in, unsigned char* out, size_t outsz)
{
	memset(out, 0, outsz);
	for (size_t i = 0, mx = std::min(outsz, in.size()); i != mx; ++i)
		out[i] = toupper(in[i]);
}

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

bool des_create2(const unsigned char* in, size_t insz, unsigned char* out, size_t outsz)
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
