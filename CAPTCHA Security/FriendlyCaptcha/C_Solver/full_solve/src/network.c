#include "curl.h"
#include "network.h"

// Write callback which does nothing
size_t noop_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    // Just return the number of bytes received, without doing anything with them
    return size * nmemb;
}

struct MemoryStruct
{
    char *memory;
    size_t size;
};

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = NULL;
    if ((ptr = realloc(mem->memory, mem->size + real_size + 1)) == NULL)
    {
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->memory[mem->size] = '\0';
    return real_size;
}

int get_puzzle(char **response)
{
    if (response == NULL)
    {
        return -1;
    }

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = NULL;
    chunk.size = 0;

    if ((curl = curl_easy_init()) != NULL)
    {
        // Disable https certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_URL, FRIENDLY_CAPTCHA_API_ENDPOINT);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
        // curl_easy_setopt(curl, CURLOPT_PROXY, RECEIVE_SOCKS5_PROXY);

        if ((res = curl_easy_perform(curl)) != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return -1;
        }

        *response = chunk.memory;
        curl_easy_cleanup(curl);
    }
    else
    {
        return -1;
    }

    return 0;
}

void send_solution(const char *solution)
{
    if (solution == NULL)
    {
        return;
    }

    CURL *curl;
    CURLcode res;
    long response_code;

    // Init curl
    if ((curl = curl_easy_init()) != NULL)
    {
        // Disable https certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Disable handling of writebacks to prevent terminal print out
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, noop_write_callback);

        // Set url, data, proxy and user agent
        curl_easy_setopt(curl, CURLOPT_URL, POST_ENDPOINT);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, solution);

        // Uncomment for socks5 proxy
        // curl_easy_setopt(curl, CURLOPT_PRE_PROXY, SEND_SOCKS5_PROXY);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);

        if ((res = curl_easy_perform(curl)) != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            // Get the response code
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code != 200)
            {
                fprintf(stderr, "Got response code %ld while sending data\n", response_code);
            }
            else
            {
                fprintf(stdout, "Solution submission successful\n");
            }
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }
}
