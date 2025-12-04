#ifndef SEND_SOLUTION_H
#define SEND_SOLUTION_H

#include "curl.h"

#define FRIENDLY_CAPTCHA_API_ENDPOINT "https://api.friendlycaptcha.com/api/v1/puzzle?sitekey=FCMGEMUD2KTDSQ5H"
#define POST_ENDPOINT "https://friendlycaptcha.com/demo"
#define RECEIVE_SOCKS5_PROXY "socks5://127.0.0.1:9050"
#define SEND_SOCKS5_PROXY "socks5://127.0.0.1:9051"

#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/119.0"

int get_puzzle(char **response);
void send_solution(const char *solution);

#endif