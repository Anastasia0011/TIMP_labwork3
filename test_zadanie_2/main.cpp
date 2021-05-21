#include <UnitTest++/UnitTest++.h>
#include "/home/student/timp_laba_1/project_2/Routechange.h"
#include "/home/student/timp_laba_1/project_2/Routechange.cpp"
#include <iostream>
#include <locale>
#include <codecvt>
using namespace std;
struct KeyB_fixture {
    Cipher * p;
    KeyB_fixture()
    {
        p = new Cipher(L"4");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};
wstring_convert <std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("С-ААРТКО", codec.to_bytes(Cipher(L"4").encrypt(L"КРАСОТА")));
    }
    TEST(LongKey) {
        CHECK_EQUAL("-АТОСАРК",codec.to_bytes(Cipher(L"8").encrypt(L"КРАСОТА")));
    }
    TEST(NegativeKey) {
        CHECK_THROW(Cipher cp(L"-3"),cipher_error);
    }
    TEST(PunctuationInKey) {
        CHECK_THROW(Cipher cp(L"ГЫ()ГЫ"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(Cipher cp(L"9 9"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(Cipher cp(L""),cipher_error);
    }
    TEST(AlphaAndPunctuationInKey) {
        CHECK_THROW(Cipher cp(L"ХАЙ1!!!"),cipher_error);
    }
}
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("С-ААРТКО",
                    codec.to_bytes(p->encrypt(L"КРАСОТА")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("С-ААРТКО",
                    codec.to_bytes(p->encrypt(L"красота")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("С-ААРТКО",
                    codec.to_bytes(p->encrypt(L"К Р?А С О.Т А")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("С-ААРТКО", codec.to_bytes(p->encrypt(L"КРА4СОТ9А")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"55559"),cipher_error);
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("КРАСОТА",
                    codec.to_bytes(p->decrypt(L"С-ААРТКО")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"С-ААрТКО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"С-ААР ТКО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"С-22ААРТКО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"С-АА,Р,ТКО"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}
int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
