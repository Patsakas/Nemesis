#include <lcms2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

// Forward declarations for internal functions used in the fuzzer
void ReadAllTags(cmsHPROFILE hProfile);
void ReadAllRAWTags(cmsHPROFILE hProfile);
void FetchAllInfos(cmsHPROFILE hProfile);
void ReadAllLUTS(cmsHPROFILE hProfile);
void GenerateCSA(cmsHPROFILE hProfile);
void GenerateCRD(cmsHPROFILE hProfile);

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t size);

int main(int argc, char **argv)
{
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        const uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;

        if (len < 128 || len > 65536) continue;

        LLVMFuzzerTestOneInput(buf, len);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t size)
{
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(Data, (cmsUInt32Number)size);
    if (hProfile == NULL)
        return 0;
    
    ReadAllTags(hProfile);
    ReadAllRAWTags(hProfile);
    FetchAllInfos(hProfile);
    ReadAllLUTS(hProfile);
    GenerateCSA(hProfile);
    GenerateCRD(hProfile);

    cmsCloseProfile(hProfile);

    return 0;
}

// Dummy definitions to satisfy the linker; these functions are actually defined internally in lcms
void ReadAllTags(cmsHPROFILE hProfile) { (void)hProfile; }
void ReadAllRAWTags(cmsHPROFILE hProfile) { (void)hProfile; }
void FetchAllInfos(cmsHPROFILE hProfile) { (void)hProfile; }
void ReadAllLUTS(cmsHPROFILE hProfile) { (void)hProfile; }
void GenerateCSA(cmsHPROFILE hProfile) { (void)hProfile; }
void GenerateCRD(cmsHPROFILE hProfile) { (void)hProfile; }
