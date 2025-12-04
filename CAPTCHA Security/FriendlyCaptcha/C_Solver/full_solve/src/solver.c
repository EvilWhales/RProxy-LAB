#include <stdio.h>

#include "solver.h"
#include "blake2.h"
#include "base64.h"
#include "network.h"

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

void reset_tor_proxy()
{
    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe, hWritePipe;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD read, dwExitCode;
    CHAR buffer[15]; // Adjust buffer size as necessary
    ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    {
        fprintf(stderr, "CreatePipe failed\n");
        return;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    // Set up members of the STARTUPINFO structure
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process
    if (!CreateProcess(NULL, "cmd.exe /c" RESET_TOR_COMMAND, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        fprintf(stderr, "CreateProcess failed (%lu)\n", GetLastError());
        return;
    }

    // Close the write end of the pipe before reading from the read end of the pipe
    CloseHandle(hWritePipe);

    // Read output from the child process's pipe for STDOUT
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &read, NULL) != FALSE)
    {
        buffer[read] = '\n';
        fwrite(buffer, sizeof(CHAR), read, stdout);
    }

    // Wait for the child process to exit and get its exit code
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &dwExitCode);

    // Close handles
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
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
    uint32_t *p_value = (uint32_t *)hash;

    if (blake2b(hash, sizeof(hash), taskContext->puzzle, taskContext->puzzle_size, NULL, 0) != 0)
    {
        return;
    }

    for (; (*p_value) >= taskContext->threshold;)
    {
        (*((unsigned int *)&(taskContext->puzzle[124])) += 1);
        if (blake2b(hash, sizeof(hash), taskContext->puzzle, taskContext->puzzle_size, NULL, 0) != 0)
        {
            return;
        }
    }
}

DWORD WINAPI process_and_send_solution(LPVOID lpParam)
{
    SolveThreadParams *params = (SolveThreadParams *)lpParam;

    uint8_t raw_solution_buffer[SOLUTION_SIZE * (params->puzzleNumber)];

    for (uint32_t i = 0; i < (params->puzzleNumber); i++)
    {
        memcpy(raw_solution_buffer + (i * SOLUTION_SIZE), (params->puzzleArray[i]) + (PUZZLE_TO_SOLVE_SIZE - SOLUTION_SIZE), SOLUTION_SIZE);
    }


    char base64_solution_buffer[BASE64_ENCODE_OUT_SIZE(sizeof(raw_solution_buffer))];
    uint32_t bytes_encoded = base64_encode(raw_solution_buffer, sizeof(raw_solution_buffer), base64_solution_buffer);

    fwrite(base64_solution_buffer, bytes_encoded, 1, stdout);
    size_t final_solution_size = strlen((params->puzzleString)) + 1 + bytes_encoded + 1;
    char final_solution_buffer[final_solution_size];

    memcpy(final_solution_buffer, (params->puzzleString), strlen((params->puzzleString)));
    final_solution_buffer[strlen((params->puzzleString))] = '.';
    memcpy(final_solution_buffer + strlen((params->puzzleString)) + 1, base64_solution_buffer, bytes_encoded);
    final_solution_buffer[final_solution_size - 1] = '\0';

    // send_solution(final_solution_buffer);

    // fwrite(final_solution_buffer, 1, strlen((const char *)final_solution_buffer), stdout);

    // Free memory
    free(params->puzzleString);
    free(params);

    return EXIT_SUCCESS;
}
