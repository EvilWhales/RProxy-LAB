#include "manage_puzzle.h"
#include "cJSON.h"
#include "base64.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *extract_puzzle_cjson(const char *json_str)
{
    char *result = NULL;
    cJSON *parsed_json = cJSON_Parse(json_str);
    if (parsed_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return NULL;
    }

    cJSON *data = cJSON_GetObjectItemCaseSensitive(parsed_json, "data");
    if (cJSON_IsObject(data))
    {
        cJSON *puzzle = cJSON_GetObjectItemCaseSensitive(data, "puzzle");
        if (cJSON_IsString(puzzle) && (puzzle->valuestring != NULL))
        {
            // Dynamically allocate memory for the result
            result = strdup(puzzle->valuestring);
        }
    }

    cJSON_Delete(parsed_json);
    return result;
}

int split_and_decode(const char *puzzle, uint8_t **decodedOutput)
{
    if (puzzle == NULL || decodedOutput == NULL)
    {
        return -1;
    }

    char *dot_offset = strchr(puzzle, '.');
    if (dot_offset == NULL)
    {
        fprintf(stderr, "Could not find dot in string\n");
        return -1;
    }

    // Increment dot_offset to point to the character after the dot (which should be 'Z')
    dot_offset++;

    // Calculate the length from the position after the dot to the end of the string
    size_t encoded_length = strlen(dot_offset);

    if((*decodedOutput = calloc(encoded_length, sizeof(uint8_t))) == NULL)
    {
        fprintf(stderr, "Failed to allocate decodedOutput\n");
        return -1;
    }

    // Return zero on success
    return !(base64_decode(dot_offset, encoded_length, *decodedOutput) > 0);
}

int create_puzzles(uint8_t *input, uint32_t number_of_puzzles, uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE])
{
    if (input == NULL || number_of_puzzles == 0)
    {
        return -1;
    }

    for (uint32_t i = 0; i < number_of_puzzles; i++)
    {
        // Copy puzzle string
        memcpy(puzzle_array[i], input, PUZZLE_STRING_LENGTH);

        // Adjust index 120
        puzzle_array[i][120] = i;
    }

    return 0;
}