#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h> // select 함수를 위해 추가
#include <time.h>       // 시간 관련 함수 추가

#define BUF_SIZE 1024
#define ID_LEN 50 // 서버와 동일하게 ID_LEN 정의
#define XOR_KEY 0x5A // XOR 암호화 키 (예시로 사용, 실제로는 더 안전한 키를 사용해야 함)

// 전역 변수
int sock; // 서버와 연결된 소켓
volatile int in_chat_mode = 0;
char username[ID_LEN]; // 로그인 성공 후 사용자 ID 저장
char name[ID_LEN];     // 로그인 성공 후 사용자 이름(닉네임) 저장
volatile int is_logged_in = 0; // 로그인 상태 플래그 (-1: 종료, 0: 초기 메뉴, 1: 로그인 성공)
pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER; // 콘솔 출력 보호용 뮤텍스
pthread_mutex_t sock_write_mutex = PTHREAD_MUTEX_INITIALIZER; // 소켓\ 쓰기 보호용 뮤텍스

// 사용자 입력 상태 플래그 (volatile로 선언하여 컴파일러 최적화 방지)
// send_msg 스레드가 사용자 입력을 기다리는 중인지 여부를 나타냅니다.
volatile int input_active = 0; 


// 현재 시간을 [시:분] 형태로 반환하는 함수
void get_current_time(char* time_str) {
    time_t now;
    struct tm* local_time;
    
    time(&now);
    local_time = localtime(&now);
    
    sprintf(time_str, "[%02d:%02d]", local_time->tm_hour, local_time->tm_min);
}

// 에러 출력 및 프로그램 종료 함수
void error_handling(const char *msg) {
    perror(msg);
    exit(1);
}

// 아스키 화면 고정
void print_fixed_header() 
{
    printf("\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡟⣍⠍⡩⡩⢉⠍⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⡇⠈⠀⠈⠁⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠶⠞⠛⠛⠛⠛⠛⠛⠳⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⣀⣀⣀⣀⡀⠀⠀⢀⣀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠹⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⢹⡇⣀⡴⠛⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠋⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢦⣄⣀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠛⠛⠛⠛⢶⣌⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣙⠍⡙⢍⣿⢹⠹⡹⡹⢙⢽⢽⢹⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣶⣦⣷⣼⣿⣾⣼⣶⣵⣿⣼⣾⣼⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⢠⡤⠀⣀⣀⣀⣀⡀⣤⠀⠀⣤⣤⣤⠀⢠⡄⠀⢀⣀⣀⣀⡀⢠⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠂⠀⠰⣿⠀⠈⢹⣿⡉⠀⣿⣤⠰⠶⠶⠶⠶⢸⡇⠀⠀⠉⠉⣿⠂⢸⡧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣄⠀⢘⣯⠀⠰⠟⠉⠷⠀⣿⠀⠀⣾⠛⢳⡄⢸⡟⠃⠀⠀⢀⣿⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡾⠃⠹⡦⢘⣯⠀⠀⠛⠛⠛⠛⣿⠀⠀⠻⣤⠾⠃⢸⡇⠀⠠⣴⠞⠃⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠈⠃⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n");
    printf("\n"); // 아스키 아트 뒤에 줄 바꿈 추가
}

void send_with_length(int target_sock, const char* msg) {
    pthread_mutex_lock(&sock_write_mutex); // 소켓 쓰기 보호
    int msg_len = strlen(msg) + 1; // 널 종료 문자 포함
    int net_msg_len = htonl(msg_len);
    if (write(target_sock, &net_msg_len, sizeof(net_msg_len)) != sizeof(net_msg_len)) {
        perror("Failed to send message length");
        pthread_mutex_unlock(&sock_write_mutex);
        return;
    }
    if (write(target_sock, msg, msg_len) != msg_len) {
        perror("Failed to send message body");
        pthread_mutex_unlock(&sock_write_mutex);
        return;
    }
    pthread_mutex_unlock(&sock_write_mutex); // 소켓 쓰기 보호 해제
}

// 메시지를 길이 기반으로 안전하게 전송하는 함수
// 사용자 입력을 받아 서버로 전송하는 스레드 함수 (로그인 후 메인 메뉴 및 채팅 전용)
void* send_msg(void* arg) {
    char buf[BUF_SIZE];
    int in_personal_menu = 0; // 개인정보 변경 메뉴에 있는지 여부
    int expecting_confirmation = 0; // Y/N 확인을 기다리는 중인지
    int expecting_new_data = 0; // 새로운 데이터 입력을 기다리는 중인지
    
    // 로그인/회원가입 프로세스가 완료될 때까지 대기
    while (is_logged_in == 0) {
        if (is_logged_in == -1) return NULL; // 프로그램 종료 플래그 감지
        usleep(100000); // 100ms 대기 (바쁜 대기 방지)
    }

    if (is_logged_in == -1) return NULL; // 대기 중 프로그램 종료 시 스레드 종료

    // 메인 메뉴 및 채팅 메시지 전송 루프
    while (1) {
        if (is_logged_in == -1) break; // 수신 스레드가 종료 플래그 설정 시 종료

        pthread_mutex_lock(&write_mutex);
        fflush(stdout);
        input_active = 1; // 입력 대기 상태 설정
        pthread_mutex_unlock(&write_mutex);

        if (fgets(buf, BUF_SIZE, stdin) == NULL) {
            fprintf(stderr, "입력 오류 발생\n");
            break;
        }
        buf[strcspn(buf, "\n")] = 0; // 개행 문자 제거

        pthread_mutex_lock(&write_mutex);
        input_active = 0; // 입력 대기 상태 해제
        pthread_mutex_unlock(&write_mutex);

        // 채팅 모드 감지 및 상태 관리
         if (!in_personal_menu && !in_chat_mode) {
            // 메인 메뉴에서
            if (strcmp(buf, "1") == 0) {
                in_personal_menu = 1; // 개인정보 변경 메뉴 진입
            } else if (strcmp(buf, "2") == 0) {
                in_chat_mode = 1; // 채팅 모드 진입
            }
        } else if (in_personal_menu) {
            // 개인정보 변경 메뉴에서
            if (strcmp(buf, "5") == 0) {
                in_personal_menu = 0; // 메인 메뉴로 돌아감
            } else if (strcmp(buf, "1") == 0 || strcmp(buf, "2") == 0 || strcmp(buf, "3") == 0) {
                expecting_confirmation = 1; // 다음에 Y/N 확인이 올 것임
            } else if (expecting_confirmation) {
                if (strcmp(buf, "Y") == 0 || strcmp(buf, "y") == 0) {
                    expecting_confirmation = 0;
                    expecting_new_data = 1; // 새로운 데이터 입력 대기
                } else if (strcmp(buf, "N") == 0 || strcmp(buf, "n") == 0) {
                    expecting_confirmation = 0; // 취소
                }
            } else if (expecting_new_data) {
                expecting_new_data = 0; // 새로운 데이터 입력 완료
            }
        } else if (in_chat_mode) {
            // 채팅 모드에서
            if (strcmp(buf, "/exit") == 0) {
                // /exit는 방만 나가기 - 서버 응답 대기
                // 서버에서 응답을 받은 후 처리
            }else {
                // 현재 시간 가져오기
                char time_str[16];
                get_current_time(time_str);
                
                // 귓속말인지 확인
                if (strncmp(buf, "/w ", 3) == 0) {
                    // 귓속말 명령어 파싱
                    char target_name[ID_LEN], body[BUF_SIZE];
                    char *p = buf + 3;
                    if (sscanf(p, "%49s %1023[^\n]", target_name, body) >= 2) {
                        // 본인 화면에 귓속말 전송 메시지 출력 (시간 포함)
                        pthread_mutex_lock(&write_mutex);
                        printf("%s [귓속말 전송] %s에게: %s\n", time_str, target_name, body);
                        pthread_mutex_unlock(&write_mutex);
                    }
                } else if (strncmp(buf, "/kick ", 6) == 0 || 
                          strncmp(buf, "/mute ", 6) == 0 || 
                          strncmp(buf, "/announce ", 10) == 0) {
                    // 관리자 명령어는 시간 표시 안 함 (서버에서 응답 받음)
                } else if (strncmp(buf, "/", 1) == 0) {
                    // 기타 명령어들 (/help, /c, /j, /l 등)은 클라이언트에서 출력하지 않음
                    // 서버에서 응답을 받아서 출력
                } else {
                    pthread_mutex_lock(&write_mutex);
                    printf("%s [%s] %s\n", time_str, name, buf);
                    pthread_mutex_unlock(&write_mutex);
                }
            }
        }
        
        send_with_length(sock, buf);
        
        // 특정 명령어 입력 시 스레드 종료 처리
        if (strcmp(buf, "3") == 0 && !in_personal_menu && !in_chat_mode) { // 메인 메뉴에서 로그아웃
            // 로그아웃 확인 및 응답을 위해 바로 종료하지 않고 서버 응답을 기다림
            // recv_msg 스레드가 서버의 "로그아웃 합니다. 서버 연결을 종료합니다." 메시지를 받고
            // 연결 종료를 감지하여 is_logged_in을 -1로 설정할 것임
            // 따라서 여기서는 바로 break하지 않고 서버 응답을 기다림
        } else if (strcmp(buf, "y") == 0 || strcmp(buf, "Y") == 0) { 
            // 로그아웃 확인에서 Y를 선택한 경우
            // 서버가 연결을 종료할 것이므로 recv_msg 스레드가 감지할 것임
            // 따라서 여기서는 특별한 처리 없이 계속 진행
        }
    }
    return NULL;
}

// 메시지를 길이 기반으로 안전하게 수신하는 함수
int receive_message(int target_sock, char* out_msg) {
    int msg_len;
    ssize_t len, total = 0;

    // 메시지 길이 수신
    while (total < sizeof(msg_len)) {
        len = read(target_sock, ((char*)&msg_len) + total, sizeof(msg_len) - total);
        if (len <= 0) return 0; // 연결 종료 또는 오류
        total += len;
    }

    msg_len = ntohl(msg_len);
    if (msg_len <= 0 || msg_len >= BUF_SIZE) {
        fprintf(stderr, " Invalid message length received : %d\n", msg_len);
        return 0;
    }

    // 실제 메시지 수신
    total = 0;
    while (total < msg_len) {
        len = read(target_sock, out_msg + total, msg_len - total);
        if (len <= 0) return 0; // 연결 종료 또는 오류
        total += len;
    }
    out_msg[msg_len - 1] = '\0'; // 널 종료
    return 1;
}

// 서버로부터 메시지를 수신하여 출력하는 스레드 함수
void* recv_msg(void* arg) {
    char msg[BUF_SIZE];
    while (1) {
        int str_len = receive_message(sock, msg);
        if (str_len == 0) { // 서버 연결 종료
            pthread_mutex_lock(&write_mutex);
            // 만약 사용자가 입력 중이었다면, 입력 라인을 정리하고 종료 메시지 출력
            if (input_active) {
                printf("\r\033[2K"); // 현재 라인 지우기
            }
            printf("\n [서버] 서버와의 연결이 끊겼습니다. 프로그램을 종료합니다.\n");
            pthread_mutex_unlock(&write_mutex);
            is_logged_in = -1; // 종료 플래그 설정
            break;
        }

        pthread_mutex_lock(&write_mutex);
        // 사용자가 현재 입력 중이고 프롬프트가 화면에 있다면,
        // 현재 라인을 지우고 메시지를 출력한 다음 프롬프트를 다시 출력
        if (input_active) {
            printf("\r\033[2K"); // 현재 라인 지우기 (ANSI 이스케이프 코드)
            printf("%s", msg); // 받은 메시지 출력 (새 줄)
            fflush(stdout); // 즉시 출력
        } else {
            // 입력 중이 아니라면 그냥 메시지 출력
            printf("%s", msg);
            fflush(stdout);
        }
        pthread_mutex_unlock(&write_mutex);

        // --- 수정된 로그인 성공 메시지 처리 ---
        if (strstr(msg, " 로그인 성공!") != NULL) {
            is_logged_in = 1;
            
            // 로그인 성공 메시지에서 사용자 정보 추출
            char *exclamation = strstr(msg, " 로그인 성공!");
            if (exclamation != NULL) {
                char *colon = strchr(exclamation + strlen(" 로그인 성공!"), ':');
                if (colon != NULL) {
                    // username 추출 (! 다음부터 : 이전까지)
                    char *username_start = exclamation + strlen(" 로그인 성공!");
                    int username_len = colon - username_start;
                    if (username_len > 0 && username_len < ID_LEN) {
                        strncpy(username, username_start, username_len);
                        username[username_len] = '\0';
                    }
                    
                    // name 추출 (: 다음부터 \n 이전까지)
                    char *name_start = colon + 1;
                    char *newline = strchr(name_start, '\n');
                    if (newline != NULL) {
                        int name_len = newline - name_start;
                        if (name_len > 0 && name_len < ID_LEN) {
                            strncpy(name, name_start, name_len);
                            name[name_len] = '\0';
                        }
                    } else {
                        // 개행이 없는 경우 끝까지 복사
                        if (strlen(name_start) < ID_LEN) {
                            strcpy(name, name_start);
                            // 혹시 뒤에 공백이나 특수문자가 있다면 제거
                            name[strcspn(name, " \t\r\n")] = '\0';
                        }
                    }
                    
                    printf("[디버그] 파싱된 사용자 정보 - ID: '%s', 이름: '%s'\n", username, name);
                }
            }
        }
        
        if (strstr(msg, " 채팅을 종료하고 메인 메뉴로 돌아갑니다") != NULL) {
            in_chat_mode = 0; // 채팅 모드 종료
        }
        // 추가: /exit로 방을 나갔을 때는 채팅 모드 유지
        if (strstr(msg, " 방을 나가서 전체 채팅방으로 이동했습니다") != NULL) {
            // 채팅 모드는 유지, 단지 방만 변경됨
        }
    }
    return NULL;
}

// 클라이언트의 초기 로그인/회원가입 프로세스를 처리하는 함수
int client_login_process(int sock) {
    char input_buf[BUF_SIZE];
    
    // 이 루프는 is_logged_in이 1 (로그인 성공) 또는 -1 (종료)이 될 때까지 계속됩니다.
    while (is_logged_in == 0) {
        pthread_mutex_lock(&write_mutex);
        fflush(stdout);
        pthread_mutex_unlock(&write_mutex);

        if (fgets(input_buf, BUF_SIZE, stdin) == NULL) {
            fprintf(stderr, "입력 오류 발생\n");
            return 0; // 오류 발생 시 종료
        }
        input_buf[strcspn(input_buf, "\n")] = 0; // 개행 문자 제거

        send_with_length(sock, input_buf); // 서버로 메뉴 선택 전송

        if (strcmp(input_buf, "1") == 0) { // 회원가입 선택
            int signup_completed = 0;
            // 회원가입 프로세스
            while (!signup_completed && is_logged_in == 0) {
                pthread_mutex_lock(&write_mutex);
                fflush(stdout);
                pthread_mutex_unlock(&write_mutex);
                
                if (fgets(input_buf, BUF_SIZE, stdin) == NULL) return 0;
                input_buf[strcspn(input_buf, "\n")] = 0;
                send_with_length(sock, input_buf);
                
                // 회원가입 성공 메시지 확인을 위한 대기
                usleep(200000); // 200ms 대기
                
                // 서버로부터 메시지를 확인하여 회원가입 완료 여부 판단
                // recv_msg 스레드가 처리하므로 여기서는 단순히 대기
                // 회원가입이 완료되면 서버가 다시 메인 메뉴를 보낼 것임
            }
            // 회원가입 완료 후 다시 메인 메뉴로 돌아감
            continue;
            
        } else if (strcmp(input_buf, "2") == 0) { // 로그인 선택
            // ID, PW 입력 루프
            while(is_logged_in == 0) {
                pthread_mutex_lock(&write_mutex);
                fflush(stdout);
                pthread_mutex_unlock(&write_mutex);
                if (fgets(input_buf, BUF_SIZE, stdin) == NULL) return 0;
                input_buf[strcspn(input_buf, "\n")] = 0;
                send_with_length(sock, input_buf);
                usleep(100000); // 서버 응답 대기
            }
            break; // 로그인 완료
            
        } else if (strcmp(input_buf, "3") == 0) { // 종료 선택
            usleep(100000); // 100ms 대기
            
            pthread_mutex_lock(&write_mutex);
            // printf("> "); // 클라이언트 측 프롬프트
            fflush(stdout);
            pthread_mutex_unlock(&write_mutex);
            
            if (fgets(input_buf, BUF_SIZE, stdin) == NULL) return 0;
            input_buf[strcspn(input_buf, "\n")] = 0; // 개행 문자 제거
            
            send_with_length(sock, input_buf);
            
            usleep(100000); // 서버 응답 대기
            
            if (strcmp(input_buf, "y") == 0 || strcmp(input_buf, "Y") == 0) {
                return 0; // 종료를 나타냄
            }
            continue;
        } else {
            // 잘못된 입력, 서버가 다시 메뉴를 보낼 것이므로 루프를 계속합니다.
            usleep(100000); // 서버 응답 대기
        }
    }
    return (is_logged_in == 1) ? 1 : 0; // 로그인 성공 시 1, 그 외 0 반환
}


int main(int argc, char *argv[]) {
    struct sockaddr_in serv_adr;
    pthread_t send_thread, recv_thread;

    if (argc != 3) {
        printf("Usage : %s <IP> <PORT>\n", argv[0]);
        exit(1);
    }

    // 소켓 생성
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        error_handling("socket() error");

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_adr.sin_port = htons(atoi(argv[2]));

    // 서버 연결
    if (connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("connect() error");
    else
        printf("--------------------------------------------------------------------\n");
        printf("               [클라이언트] 서버에 연결되었습니다.\n");
        printf("--------------------------------------------------------------------\n");

    // 아스키 함수
    
    print_fixed_header();

    // 수신 스레드 생성
    pthread_create(&recv_thread, NULL, recv_msg, NULL);
    pthread_detach(recv_thread); // 스레드 자동 소멸 설정

    // 초기 로그인/회원가입 프로세스 처리
    // 이 함수는 로그인 성공 또는 프로그램 종료 시까지 블로킹됩니다.
    int login_success = client_login_process(sock);

    if (login_success) {
        // 로그인/회원가입이 성공적으로 완료되면,
        // 메인 메뉴 및 채팅 메시지 전송을 담당할 send_msg 스레드를 생성합니다.
        pthread_create(&send_thread, NULL, send_msg, NULL);
        pthread_detach(send_thread); // 스레드 자동 소멸 설정
    } else {
        // client_login_process에서 종료(3번 선택 또는 오류)되었다면,
        // 메인 루프를 종료하도록 is_logged_in을 -1로 설정합니다.
        is_logged_in = -1;
    }

    // 메인 스레드는 프로그램 종료 플래그가 설정될 때까지 대기
    while(is_logged_in != -1) {
        sleep(1); // 스레드들이 작업을 수행할 수 있도록 잠시 대기
    }
    
    // 소켓 닫기
    close(sock);
    return 0;
}