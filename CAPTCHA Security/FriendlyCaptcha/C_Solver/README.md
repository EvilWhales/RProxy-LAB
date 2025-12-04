# C Solver

### full_solve

[full_solve](./full_solve/) is designed to run on Windows systems only. Default domain is set to the [Friendly Captcha demo site](https://friendlycaptcha.com/demo).

In order to disable reloading at a threshold comment out block at `if (splitted_and_decoded_puzzle[PUZZLE_THRESHOLD_INDEX] > 165)` in the file [main.c](./full_solve/src/main.c). The default is set to use WSL 2 Tor Proxy running at port 9050. Make sure to set the suid to `/usr/sbin/service` inside WSL. Or just implement your own proxy.

#### Building and running

```bash
# Build
make

# Run
/bin/solver.exe
```

### only_puzzle_solve

[only_puzzle_solve](./only_puzzle_solve/) is designed to process puzzles passed in via cli argument and print full result to `stdout`. 

#### Building and running

```bash
# Build
make

# Example Run
/bin/solver.exe 8d998e77c060f84f8b5754ed31093b21.ZWJLogdbzRU63mixAQwtkgAAAAAAAAAA0Op1J4JNfek=
```