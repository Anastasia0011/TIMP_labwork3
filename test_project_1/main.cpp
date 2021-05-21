#include <UnitTest++/UnitTest++.h>
#include "/home/student/timp_laba_1/project_1/modAlphaCipher.h"
#include "/home/student/timp_laba_1/project_1/modAlphaCipher.cpp"

using namespace std;
struct KeyB_fixture {
	modAlphaCipher * p;
	KeyB_fixture()
	{
		p = new modAlphaCipher(L"Б");
	}
	~KeyB_fixture()
	{
		delete p;
	}
};
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
	TEST(ValidKey) {
		CHECK_EQUAL("АБВАБ", codec.to_bytes(modAlphaCipher(L"АБВ").encrypt(L"ААААА")));
	}
	TEST(LongKey) {
		CHECK_EQUAL("АБВГД",codec.to_bytes(modAlphaCipher(L"АБВГДЕЁЖЗ").encrypt(L"ААААА")));
	}
	TEST(LowCaseKey) {
		CHECK_EQUAL("АБВАБ",codec.to_bytes(modAlphaCipher(L"абв").encrypt(L"AAAAA")));
	}
	TEST(DigitsInKey) {
		CHECK_THROW(modAlphaCipher cp(L"Б1"),cipher_error);
	}
	TEST(PunctuationInKey) {
		CHECK_THROW(modAlphaCipher cp(L"А,Б"),cipher_error);
	}
	TEST(WhitespaceInKey) {
		CHECK_THROW(modAlphaCipher cp(L"А Б"),cipher_error);
	}
	TEST(EmptyKey) {
		CHECK_THROW(modAlphaCipher cp(L""),cipher_error);
	}
	TEST(WeakKey) {
		CHECK_THROW(modAlphaCipher cp(L"ААА"),cipher_error);
	}
}
SUITE(EncryptTest)
{
	TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("НБНБНЬМБСБНФ",
		            codec.to_bytes(p->encrypt(L"МАМАМЫЛАРАМУ")));
	}
	TEST_FIXTURE(KeyB_fixture, LowCaseString) {
		CHECK_EQUAL("НБНБНЬМБСБНФ",
		            codec.to_bytes(p->encrypt(L"мамамылараму")));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
		CHECK_EQUAL("НБНБНЬМБСБНФ",
		            codec.to_bytes(p->encrypt(L"МАМА МЫЛА РАМУ")));
	}
	TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
		CHECK_EQUAL("ТОПГЬН2177ДПЕПН", codec.to_bytes(p->encrypt(L"С Новым 2177 годом!!!")));
	}
	TEST_FIXTURE(KeyB_fixture, EmptyString) {
		CHECK_THROW(p->encrypt(L""),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
		CHECK_THROW(p->encrypt(L"1234+8765=9999"),cipher_error);
	}
	TEST(MaxShiftKey) {
		CHECK_EQUAL("МАМАМЫЛАРАМУ",
		            codec.to_bytes(modAlphaCipher(L"Я").encrypt(L"ЛЯЛЯЛЪКЯПЯЛТ")));
	}
}
SUITE(DecryptText)
{
	TEST_FIXTURE(KeyB_fixture, UpCaseString) {
		CHECK_EQUAL("МАМАМЫЛАРАМУ",
		codec.to_bytes(p->decrypt(L"НБНБНЬМБСБНФ")));
	}
	TEST_FIXTURE(KeyB_fixture, LowCaseString) {
		CHECK_THROW(p->decrypt(L"нбНБНЬМБСБНФ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
		CHECK_THROW(p->decrypt(L"НБНБ НЬМБ СБНФ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, DigitsString) {
		CHECK_THROW(p->decrypt(L"ТОПГЬН2177ДПЕПН"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, PunctString) {
		CHECK_THROW(p->decrypt(L"НБНБ,НЬМБСБНФ"),cipher_error);
	}
	TEST_FIXTURE(KeyB_fixture, EmptyString) {
		CHECK_THROW(p->decrypt(L""),cipher_error);
	}
	TEST(MaxShiftKey) {
		CHECK_EQUAL("ЛЯЛЯЛЪКЯПЯЛТ",
		            codec.to_bytes(modAlphaCipher(L"Я").decrypt(L"МАМАМЫЛАРАМУ")));
	}
}
int main()
{
	locale loc("ru_RU.UTF-8");
	locale::global(loc);
	return UnitTest::RunAllTests();
}