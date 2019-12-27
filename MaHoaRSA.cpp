#pragma warning(disable:4996)
#include <stdint.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cmath>
#include <cstdio>
using namespace std;

bool CheckIsPrime(int64_t);
bool CheckCoPrime(int64_t, int64_t);
int64_t Multiply(int64_t, int64_t);
int64_t FindE(int64_t);
int64_t FindD(int64_t, int64_t);
int64_t Encrypt_Decrypt(int64_t, int64_t, int64_t);
//void EncDecStr(int64_t, int64_t);
void EncryptStr(int64_t, int64_t, char *);
void DecryptStr(int64_t, int64_t, char *);
void StringSplit(char *, char *, int, int);
void EncDecNum(int64_t, int64_t);
void generate_key(int64_t &, int64_t &, int64_t &);
int64_t OS2IP(char *);
char* I2OSP(int64_t, int);


int main()
{
	cout << "==== RSA ALGORITHM ====" << endl << endl;
	int64_t n, d = 0, e;
	int count = 0;
	generate_key(n, e, d);
	cout << "Public Key: (e, n) = (" << e << "," << n << ")" << endl;
	cout << "Private Key: (d, n) = (" << d << "," << n << ")" << endl;
	cout << "\n1: Ma hoa so" << endl;
	cout << "2: Ma hoa chuoi" << endl;
	cout << "Chon: ";
	int choice;
	cin >> choice;
	switch (choice)
	{
	case 1:
		EncDecNum(e, n);
		break;
	case 2:
	{
		char *BanRo = new char[1000];
		cout << "\nNhap ban ro: ";
		rewind(stdin);
		cin.getline(BanRo, 1000);
		EncryptStr(e, n, BanRo);
		delete[] BanRo;
		break;
	}

	default:
		cout << "Chon lai!" << endl;
		exit(1);

	}
	cout << "1: Giai ma so" << endl;
	cout << "2: Giai ma chuoi " << endl;
	cout << "Chon: ";
	cin >> choice;
	switch (choice)
	{
	case 1:
		EncDecNum(d, n);
		break;
	case 2:
	{
		char *BanMa = new char[1000];
		cout << "\nNhap ban ma (hex): ";
		cin >> BanMa;
		DecryptStr(d, n, BanMa);
		delete[] BanMa;
		break;
	}
	default:
		cout << "Chon lai!" << endl;
		exit(1);
	}

	system("pause");
	return 0;
}

/*
- Điều kiện
d.e = 1 mod(phi_n)
e < n
d < n
*/

/*
** Quá trình tạo khóa
1. Chọn ngẫu nhiên hai số nguyên tố lớn p và q (p khác q)
2. Tính n = p*q
3. Tính giá trị hàm số Ơ-le: phi_n = (p-1)*(q-1)
4. Chọn một số tự nhiên e (sao cho 1 < e < phi_n và UCLN(e, phi_n) = 1)
5. Tính d sao cho d*e = 1(mod(phi_n))
Khóa công khai (Khóa mã hóa): (e, n)
Khóa bí mật (Khóa giải mã): (d, n)
** Quá trình mã hóa
- Thông điệp cần mã hóa M được chuyển thành số m (m < n)
- Bản mã c được tính theo công thức:
c = (m^e) mod n
** Quá trình giải mã
- Bản rõ là số m được tính theo công thức:
m = (c^d) mod n
- số m được chuyển ngược lại trở về thành thông điệp M như ban đầu
*/

//Kiểm tra số nguyên tố
bool CheckIsPrime(int64_t num) {
	if (num < 2) return false;
	int64_t i = 2;
	while (i <= num / 2) {
		if (!(num % i)) return false;
		i++;
	}
	return true;
}
bool CheckCoPrime(int64_t num1, int64_t num2)
{   // Kiểm tra hai số có nguyên tố cùng nhau hay không
	int64_t a, b, r;
	bool isCoprime;
	if (num1 > num2)
	{
		a = num1;
		b = num2;
	}
	else
	{
		a = num2;
		b = num1;
	}
	while (b != 0)
	{
		r = a % b;
		a = b;
		b = r;
	}

	if (a == 1) isCoprime = true;
	else isCoprime = false;

	return isCoprime;
}

int64_t Multiply(int64_t num1, int64_t num2)
{
	return num1 * num2;
}
//Tính số mũ e
int64_t FindE(int64_t phi_n)
{
	int64_t e = 0;
	do
	{
		cout << "Nhap so e (1 < e < phi_n; UCLN(e, phi_n) = 1): ";
		cin >> e;
	} while (!CheckCoPrime(phi_n, e) || e <= 1 || e >= phi_n);

	return e;
}

//Tính d
int64_t FindD(int64_t phi_n, int64_t e)
{
	int64_t r, i;
	for (int i = 1; i < phi_n; i++)
	{
		if ((i*e) % phi_n == 1)
		{
			r = i;
			break;
		}
	}

	return r;
}

//mã hóa hoặc giải mã thông qua các biến truyền vào
int64_t Encrypt_Decrypt(int64_t t, int64_t e, int64_t n)
{
	int64_t rem;
	int64_t x = 1;
	while (e != 0) {
		rem = e % 2;
		e = e / 2;
		if (rem == 1) x = (x*t) % n;
		t = (t*t) % n;
	}
	return x;
}
void EncryptStr(int64_t e, int64_t n, char *input)
{
	// Mã hóa chuỗi ký tự: Mã hóa từng ký tự
	int64_t *result = new int64_t[1000];

	cout << "Ma hoa su dung khoa cong khai!" << endl;
	cout << "Ban ma (hex): ";
	int idx = 0;
	int LenStr = strlen(input);
	while (idx != LenStr)
	{
		result[idx] = Encrypt_Decrypt(input[idx], e, n);
		idx++;
	}
	for (int i = 0; i < idx; i++)
		cout << I2OSP(result[i], 6);
	cout << endl;
	delete[] result;
}
void StringSplit(char *input, char *output, int start, int end)
{
	// Hàm tách ra một chuỗi con từ một chuỗi lớn.
	int idx = 0;
	for (int i = start; i <= end; i++)
		output[idx++] = input[i];
	output[idx] = '\0';
}
//Giải mã chuỗi
void DecryptStr(int64_t d, int64_t n, char *input)
{
	char *BanRo = new char[1000];
	int SoOcTet = strlen(input) / 12;

	cout << "Giai ma su dung khoa bi mat!" << endl;
	cout << "Ban ro: ";
	int start = 0, index;
	for (index = 0; index < SoOcTet; index++)
	{
		char tmp[13] = "";
		int end = start + 12;
		StringSplit(input, tmp, start, end - 1);
		BanRo[index] = Encrypt_Decrypt(OS2IP(tmp), d, n);
		start += 12;
	}
	BanRo[index] = '\0';
	cout << BanRo << endl;

	delete[] BanRo;
}


void EncDecNum(int64_t n1, int64_t n2)
{
	// Mã hóa số

	int64_t pn;
	cout << "\nNhap mot so nguyen: ";
	cin >> pn;
	cout << Encrypt_Decrypt(pn, n1, n2) << endl;
}

//Sinh khóa
void generate_key(int64_t &n, int64_t &e, int64_t &d)
{
	int64_t p, q, phi_n, pt, ct;

	do
	{
		cout << "Nhap so nguyen to p = ";
		cin >> p;
	} while (!CheckIsPrime(p));

	do
	{
		cout << "Nhap so nguyen to q = ";
		cin >> q;
	} while (!CheckIsPrime(q));

	n = Multiply(p, q);
	cout << "So modun cong khai: n = p * q =  " << n << endl;
	phi_n = Multiply(p - 1, q - 1);
	cout << "Gia tri ham so O-le: phi_n = " << phi_n << endl;

	// Tìm E
	e = FindE(phi_n);
	cout << "So mu cong khai: e = " << e << endl;
	if (!e)
	{
		cout << "Choose two suitable prime number" << endl;
		exit(1);
	}

	// Tìm D
	d = FindD(phi_n, e);
	cout << "So mu bi mat: d = " << d << endl;
}
int64_t OS2IP(char *s)
{	// Octet String To Integer Primitive
	// Hàm chuyển đổi chuỗi hệ 16 sang một số nguyên hệ 10
	int Dec = 0;
	int length = strlen(s);
	int somu = length - 1;

	for (int i = 0; i < length; i++)
	{
		int so;
		if (s[i] == 'A' || s[i] == 'a')
			so = 10;
		else if (s[i] == 'B' || s[i] == 'b')
			so = 11;
		else if (s[i] == 'C' || s[i] == 'c')
			so = 12;
		else if (s[i] == 'D' || s[i] == 'd')
			so = 13;
		else if (s[i] == 'E' || s[i] == 'e')
			so = 14;
		else if (s[i] == 'F' || s[i] == 'f')
			so = 15;
		else if (s[i] >= '0' && s[i] <= '9')
			so = s[i] - 48;
		Dec += so * pow((double)16, somu--);
	}
	return Dec;
}
char* I2OSP(int64_t Dec, int length)
{	// Integer To Octet String Primitive
	// Hàm chuyển một số nguyên hệ 10 sang chuỗi hệ 16
	int idx = 0;
	char *kq = new char[(length * 2) + 1];
	while (Dec != 0)
	{
		int so = Dec % 16;
		if (so <= 9)
			kq[idx++] = so + 48;
		else if (so == 10)
			kq[idx++] = 'A';
		else if (so == 11)
			kq[idx++] = 'B';
		else if (so == 12)
			kq[idx++] = 'C';
		else if (so == 13)
			kq[idx++] = 'D';
		else if (so == 14)
			kq[idx++] = 'E';
		else if (so == 15)
			kq[idx++] = 'F';

		Dec /= 16;
	}

	int max = length * 2;
	while (idx != max) {
		kq[idx++] = '0';
	}

	kq[idx] = '\0';

	strrev(kq);

	return kq;
}
