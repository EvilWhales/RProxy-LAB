#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <windows.h>
#include <Winbase.h>

#include "cJSON.h"
#include "solver.h"
#include "manage_puzzle.h"
#include "network.h"

int main()
{
    // Init curl
    if (curl_global_init(CURL_GLOBAL_ALL) != 0)
    {
        printf("curl_global_init failed");
        return EXIT_FAILURE;
    }

    while (1)
    {
        char *puzzle_string = NULL;
        char *puzzle_json_string = NULL;
        uint8_t *splitted_and_decoded_puzzle = NULL;
        int ret = 0;
        uint32_t puzzle_number = 0;
        uint32_t threshold = 0;

        // Get puzzle string from api
        if (get_puzzle(&puzzle_string) != 0)
        {
            fprintf(stderr, "Puzzle string failed\n");
            return EXIT_FAILURE;
        }

        // Get puzzle json string
        puzzle_json_string = extract_puzzle_cjson(puzzle_string);

        // Free original puzzle string
        free(puzzle_string);

        if (puzzle_json_string == NULL)
        {
            fprintf(stderr, "extract_puzzle_cjson failed\n");
            return EXIT_FAILURE;
        }

        // Fetch data from puzzle
        if (split_and_decode(puzzle_json_string, &splitted_and_decoded_puzzle) != 0)
        {
            fprintf(stderr, "split_and_decode failed\n");
            free(puzzle_json_string);
            return EXIT_FAILURE;
        }

        // Get puzzle number and threshold
        puzzle_number = GET_PUZZLE_NUMBER(splitted_and_decoded_puzzle);
        threshold = CALCULATE_DIFFICULTY_THRESHOLD(splitted_and_decoded_puzzle[PUZZLE_THRESHOLD_INDEX]);

        // fprintf(stdout, "\n\n%s\nPuzzles to solve: %u --- Threshold value: %d\n", puzzle_json_string, puzzle_number, splitted_and_decoded_puzzle[PUZZLE_THRESHOLD_INDEX]);
        fprintf(stdout, "%s\n", puzzle_json_string);

        // Check if threshold is too high
        if (splitted_and_decoded_puzzle[PUZZLE_THRESHOLD_INDEX] > 165)
        {
            fprintf(stdout, "Threshold too high...  ");
            reset_tor_proxy();
            continue;
        }

        // Create stack allocated array dynamicly and zero init
        uint8_t puzzle_array[puzzle_number][PUZZLE_TO_SOLVE_SIZE];
        memset(puzzle_array, 0, sizeof(puzzle_array));

        // Create puzzles
        ret = create_puzzles(splitted_and_decoded_puzzle, puzzle_number, puzzle_array);

        // Free decoded puzzle
        free(splitted_and_decoded_puzzle);

        if (ret != 0)
        {
            fprintf(stderr, "create_puzzles failed\n");
            free(puzzle_json_string);
            return EXIT_FAILURE;
        }

        // Solve puzzle
        ret = init_solve_puzzle(puzzle_array, puzzle_number, threshold);

        if (ret != 0)
        {
            fprintf(stderr, "init_solve_puzzle failed\n");
            free(puzzle_json_string);
            return EXIT_FAILURE;
        }

        // Allocate memory for thread parameters
        SolveThreadParams *params = malloc(sizeof(SolveThreadParams));
        params->puzzleString = puzzle_json_string;
        params->puzzleArray = puzzle_array;
        params->puzzleNumber = puzzle_number;

        // Create the thread and sending the solution | freeing is handled inside the thread
        HANDLE thread = CreateThread(NULL, 0, process_and_send_solution, params, 0, NULL);
        if (thread == NULL)
        {
            fprintf(stderr, "Error creating thread\n");
            continue;
        }

        CloseHandle(thread);
    }

    curl_global_cleanup();

    return EXIT_SUCCESS;
}