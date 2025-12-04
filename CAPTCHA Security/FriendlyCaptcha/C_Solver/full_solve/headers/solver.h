#ifndef SOLVER_H
#define SOLVER_H

#define _WIN32_WINNT 0x0700

#include <windows.h>
#include <winbase.h>
#include <stdint.h>

#define SOLUTION_SIZE 8
#define PUZZLE_TO_SOLVE_SIZE 128

#define CALCULATE_DIFFICULTY_THRESHOLD(d) ((uint32_t)pow(2, (255.999 - (d)) / 8.0))
#define GET_PUZZLE_NUMBER(puzzle) ((uint32_t)(puzzle[PUZZLE_NUMBER_INDEX]))

#define RESET_TOR_COMMAND "wsl bash -c 'sudo /usr/sbin/service tor restart; while ! curl --silent --proxy socks5://127.0.0.1:9050 https://api.ipify.org; do sleep 0.5; done'"

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

typedef struct {
    const char *puzzleString;
    uint8_t (*puzzleArray)[PUZZLE_TO_SOLVE_SIZE];
    uint32_t puzzleNumber;
} SolveThreadParams;

typedef struct
{
    uint8_t *puzzle;
    uint32_t puzzle_size;
    unsigned int threshold;
} PuzzleTaskContext;

int init_solve_puzzle(uint8_t (*puzzle_array)[PUZZLE_TO_SOLVE_SIZE], uint32_t number_of_puzzles, uint32_t threshold);
void reset_tor_proxy();
VOID CALLBACK solve_puzzle_worker(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
DWORD WINAPI process_and_send_solution(LPVOID lpParam);

#endif