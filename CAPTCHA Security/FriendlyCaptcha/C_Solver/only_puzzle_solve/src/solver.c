#include "solver.h"
#include "base64.h"
#include "blake2.h"

#include <string.h>
#include <stdio.h>

int split_and_decode(const char *puzzle, uint8_t **decodedOutput)
{
    if (puzzle == NULL || decodedOutput == NULL)
    {
        fprintf(stderr, "False args: puzzle: %d --- %d\n", puzzle == NULL, decodedOutput == NULL);
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

    if ((*decodedOutput = calloc(encoded_length, sizeof(uint8_t))) == NULL)
    {
        fprintf(stderr, "Failed to allocate decodedOutput\n");
        return -1;
    }

    printf("%s\n", dot_offset);

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

int init_solve_puzzle(uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE], uint32_t number_of_puzzles, uint32_t threshold)
{
    if (puzzle_array == NULL)
    {
        return -1;
    }

    // Task context array
    PuzzleTaskContext taskContexts[number_of_puzzles];

    // Worker array
    PTP_WORK workItems[number_of_puzzles];

    // Create thread pool
    PTP_POOL pool = CreateThreadpool(NULL);
    SetThreadpoolThreadMaximum(pool, 32);
    SetThreadpoolThreadMinimum(pool, 32);

    // Create a callback environment
    TP_CALLBACK_ENVIRON CallBackEnviron;
    InitializeThreadpoolEnvironment(&CallBackEnviron);

    // Associate the thread pool with the callback environment
    SetThreadpoolCallbackPool(&CallBackEnviron, pool);

    for (uint32_t i = 0; i < number_of_puzzles; i++)
    {
        // Prepare the context for each task
        taskContexts[i].puzzle = puzzle_array[i];
        taskContexts[i].puzzle_size = PUZZLE_TO_SOLVE_SIZE;
        taskContexts[i].threshold = threshold;

        // Create and submit work item
        workItems[i] = CreateThreadpoolWork(solve_puzzle_worker, &taskContexts[i], &CallBackEnviron);
        SubmitThreadpoolWork(workItems[i]);
    }

    // Wait and cleanup thread pool and work items
    for (uint32_t i = 0; i < number_of_puzzles; i++)
    {
        WaitForThreadpoolWorkCallbacks(workItems[i], FALSE);
        CloseThreadpoolWork(workItems[i]);
    }

    CloseThreadpool(pool);

    return 0;
}

VOID CALLBACK solve_puzzle_worker(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work)
{
    PuzzleTaskContext *taskContext = (PuzzleTaskContext *)Context;

    if (taskContext == NULL || taskContext->puzzle == NULL)
    {
        return;
    }

    // Buffer for hash
    uint8_t hash[32] = {0};

    // Value to check against the threshold | First four bytes of the hash
    uint32_t *threshold_comparison = (uint32_t *)hash;
    uint32_t *hash_increment = (uint32_t *)&(taskContext->puzzle[124]);

    if (blake2b(hash, sizeof(hash), taskContext->puzzle, taskContext->puzzle_size, NULL, 0) != 0)
    {
        return;
    } 

    for (; (*threshold_comparison) >= taskContext->threshold;)
    {
        ((*hash_increment) += 1);
        if (blake2b(hash, sizeof(hash), taskContext->puzzle, taskContext->puzzle_size, NULL, 0) != 0)
        {
            return;
        }
    }
}

void process_and_print_solution(const char *puzzleString, uint8_t (*puzzleArray)[PUZZLE_TO_SOLVE_SIZE], uint32_t puzzleNumber)
{
    uint8_t raw_solution_buffer[SOLUTION_SIZE * puzzleNumber];

    for (uint32_t i = 0; i < puzzleNumber; i++)
    {
        memcpy(raw_solution_buffer + (i * SOLUTION_SIZE), puzzleArray[i] + (PUZZLE_TO_SOLVE_SIZE - SOLUTION_SIZE), SOLUTION_SIZE);
    }

    char base64_solution_buffer[BASE64_ENCODE_OUT_SIZE(sizeof(raw_solution_buffer))];
    uint32_t bytes_encoded = base64_encode(raw_solution_buffer, sizeof(raw_solution_buffer), base64_solution_buffer);

    size_t final_solution_size = strlen(puzzleString) + 1 + bytes_encoded + 1;
    char final_solution_buffer[final_solution_size];

    memcpy(final_solution_buffer, puzzleString, strlen(puzzleString));
    final_solution_buffer[strlen(puzzleString)] = '.';
    memcpy(final_solution_buffer + strlen(puzzleString) + 1, base64_solution_buffer, bytes_encoded);
    final_solution_buffer[final_solution_size - 1] = '\0';

    fwrite(final_solution_buffer, 1, strlen((const char *)final_solution_buffer), stdout);

    return;
}
