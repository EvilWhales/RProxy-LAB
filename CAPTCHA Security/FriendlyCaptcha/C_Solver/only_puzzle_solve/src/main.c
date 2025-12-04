#include <stdlib.h>
#include <stdio.h>

#include "solver.h"

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        return EXIT_FAILURE;
    }

    uint8_t *splitted_and_decoded_puzzle = NULL;

    uint32_t puzzle_number;
    uint32_t threshold;
    int ret = 1;

    // Fetch data from puzzle
    if (split_and_decode(argv[1], &splitted_and_decoded_puzzle) != 0)
    {
        fprintf(stderr, "split_and_decode failed\n");
        return EXIT_FAILURE;
    }

    // Get puzzle number and threshold
    puzzle_number = GET_PUZZLE_NUMBER(splitted_and_decoded_puzzle);
    threshold = CALCULATE_DIFFICULTY_THRESHOLD(splitted_and_decoded_puzzle[PUZZLE_THRESHOLD_INDEX]);

    // Create stack allocated array dynamicly and zero init
    uint8_t puzzle_array[puzzle_number][PUZZLE_TO_SOLVE_SIZE];
    memset(puzzle_array, 0, sizeof(puzzle_array));

    ret = create_puzzles(splitted_and_decoded_puzzle, puzzle_number, puzzle_array);

    // Free decoded puzzle
    free(splitted_and_decoded_puzzle);

    if (ret != 0)
    {
        return EXIT_FAILURE;
    }

    if (init_solve_puzzle(puzzle_array, puzzle_number, threshold) != 0)
    {
        return EXIT_FAILURE;
    }

    process_and_print_solution(argv[1], puzzle_array, puzzle_number);

    return EXIT_SUCCESS;
}