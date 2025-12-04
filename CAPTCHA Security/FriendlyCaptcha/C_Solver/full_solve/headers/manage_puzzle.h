#ifndef MANAGE_PUZZLE_H
#define MANAGE_PUZZLE_H

#include <stdint.h>

#define PUZZLE_TO_SOLVE_SIZE 128


// Offset of puzzle after signature which is always of the same size
// Example 4145c6f10decf8050af6054759b19dbf.ZV4hhgdbzRU63mixAQwwuQAAAAAAAAAAc4tay/r3eTE=
// 33 will be the Z
// #define PUZZLE_OFFSET 33
// #define ENCODED_PUZZLE_LENGTH 44

#define PUZZLE_STRING_LENGTH 32

#define PUZZLE_NUMBER_INDEX 14
#define PUZZLE_THRESHOLD_INDEX 15


char *extract_puzzle_cjson(const char *json_str);
int split_and_decode(const char *puzzle, uint8_t **decodedOutput);
int create_puzzles(uint8_t *input, uint32_t number_of_puzzles, uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE]);

#endif