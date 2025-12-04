#ifndef SOLVER_H
#define SOLVER_H

#define _WIN32_WINNT 0x0700

#include <windows.h>
#include <winbase.h>
#include <stdint.h>
#include <math.h>

#define SOLUTION_SIZE 8
#define PUZZLE_TO_SOLVE_SIZE 128

#define CALCULATE_DIFFICULTY_THRESHOLD(d) ((uint32_t)pow(2, (255.999 - (d)) / 8.0))
#define GET_PUZZLE_NUMBER(puzzle) ((uint32_t)(puzzle[PUZZLE_NUMBER_INDEX]))

#define PUZZLE_STRING_LENGTH 32

#define PUZZLE_NUMBER_INDEX 14
#define PUZZLE_THRESHOLD_INDEX 15

int split_and_decode(const char *puzzle, uint8_t **decodedOutput);
int create_puzzles(uint8_t *input, uint32_t number_of_puzzles, uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE]);

FORCEINLINE VOID InitializeThreadpoolEnvironment(
    _Out_ PTP_CALLBACK_ENVIRON pcbe)
{
    TpInitializeCallbackEnviron(pcbe);
}

FORCEINLINE VOID SetThreadpoolCallbackPool(
    _Inout_ PTP_CALLBACK_ENVIRON pcbe,
    _In_ PTP_POOL ptpp)
{
    TpSetCallbackThreadpool(pcbe, ptpp);
}

typedef struct
{
    uint8_t *puzzle;
    uint32_t puzzle_size;
    unsigned int threshold;
} PuzzleTaskContext;

int init_solve_puzzle(uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE], uint32_t number_of_puzzles, uint32_t threshold);
VOID CALLBACK solve_puzzle_worker(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
void process_and_print_solution(const char *puzzleString, uint8_t (*puzzleArray)[PUZZLE_TO_SOLVE_SIZE], uint32_t puzzleNumber);

#endif