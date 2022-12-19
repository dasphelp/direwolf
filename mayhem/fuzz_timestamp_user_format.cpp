#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" void timestamp_user_format(char *result, int result_size, char *user_format);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* user_format = strdup(provider.ConsumeRandomLengthString(1000).c_str());
    char* buf = (char*) malloc(sizeof(char) * 1000);

    timestamp_user_format(buf, 999, user_format);

    free(buf);
    free(user_format);

    return 0;
}
