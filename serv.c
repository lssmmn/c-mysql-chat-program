#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <ctype.h> // islower, isdigit, isupper 등을 위해 추가
#include <time.h>  // 시간 관련 함수 
#include <openssl/sha.h>  // SHA-256 해시 함수 사용

#define MAX_CLIENTS 100
#define MAX_ROOMS 50 // 현재 사용되지 않음, 확장 시 필요
#define BUF_SIZE 1024
#define ID_LEN 50   // ID (username) 및 이름(name) 길이
#define ROOM_NAME_LEN 50 // 방 이름 길이 

// MySQL DB 연결 정보 (!!!! 사용자 환경에 맞게 수정해주세요 !!!!)
#define DB_HOST "localhost"
#define DB_USER "root"
#define DB_PASS "1234"       // 비밀번호
#define DB_NAME "login_db"    // 데이터베이스 이름
#define DB_PORT 3306         // MySQL 기본 포트

// 컴파일링 : gcc serv.c -o server -lmysqlclient -lpthread -lcrypto

// 클라이언트 구조체 정의
typedef struct {
    int sock;
    char username[ID_LEN];
    char name[ID_LEN];
    char room[ROOM_NAME_LEN]; 
    int is_admin;
    int is_muted;
    pthread_t tid;
} Client;

// 채팅방 구조체 정의
typedef struct {
    char name[ID_LEN];      // 방 이름
    int member_count;
} ChatRoom;

// 현재 활성화된 채팅방을 관리하기 위한 배열
ChatRoom chat_rooms[MAX_ROOMS];

// 현재 활성화된 클라이언트 수를 관리하기 위한 변수
int room_count = 0;

// Client 포인터 배열 (동적 할당된 Client 구조체 포인터를 저장)
Client* clients[MAX_CLIENTS];
int client_count = 0; // 활성화된 클라이언트 수

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
MYSQL* conn;

// 에러 출력 및 프로그램 종료 함수
void error_handling(const char *msg) {
    perror(msg);
    exit(1);
}

// 현재 시간을 [시:분] 형태로 반환하는 함수
void get_current_time(char* time_str) {
    time_t now;
    struct tm* local_time;

    time(&now);
    local_time = localtime(&now);

    sprintf(time_str, "[%02d:%02d]", local_time->tm_hour, local_time->tm_min);
}

// UTF-8 문자열의 실제 글자 수를 계산하는 함수
int utf8_strlen(const char* s) {
    int len = 0;
    if (s == NULL) return 0; // NULL 포인터 체크
    while (*s) { // 포인터 s가 가리키는 값이 널 종료 문자가 아닐 때까지
        // 현재 바이트가 UTF-8 멀티바이트 문자의 첫 번째 바이트인지 확인
        // (상위 2비트가 10이 아닌 경우, 즉 0xxxxxxx, 11xxxxxx)
        if ((*s & 0xc0) != 0x80) {
            len++;  // 첫 바이트만 카운트
        }
        s++; // 다음 바이트로 이동
    }
    return len;
}

// 메시지를 길이 기반으로 안전하게 전송하는 함수
void send_with_length(int sock, const char* msg) {
    int msg_len = strlen(msg) + 1; // 널 종료 문자 포함
    int net_msg_len = htonl(msg_len);
    if (write(sock, &net_msg_len, sizeof(net_msg_len)) != sizeof(net_msg_len)) {
        perror(" Failed to send message length");
        return;
    }
    if (write(sock, msg, msg_len) != msg_len) {
        perror(" Failed to send message body");
        return;
    }
}

// 메시지를 길이 기반으로 안전하게 수신하는 함수
int receive_message(int sock, char* out_msg) {
    int msg_len;
    ssize_t len, total = 0;

    // 메시지 길이 수신
    while (total < sizeof(msg_len)) {
        len = read(sock, ((char*)&msg_len) + total, sizeof(msg_len) - total);
        if (len <= 0) return 0; // 연결 종료 또는 오류
        total += len;
    }

    msg_len = ntohl(msg_len);
    if (msg_len <= 0 || msg_len >= BUF_SIZE) { // msg_len이 너무 크거나 0 이하인 경우 방지
        fprintf(stderr, " Invalid message length received: %d\n", msg_len);
        return 0;
    }

    // 실제 메시지 수신
    total = 0;
    while (total < msg_len) {
        len = read(sock, out_msg + total, msg_len - total);
        if (len <= 0) return 0; // 연결 종료 또는 오류
        total += len;
    }
    out_msg[msg_len - 1] = '\0'; // 널 종료
    return 1;
}

//비밀번호를 SHA-256 해시로 변환하는 함수
void hash_256_password(const char* password, char* hashed_output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_output + (i * 2), "%02x", hash[i]);
    }
    hashed_output[64] = '\0';  // 널 종료 문자
}


// MySQL에 사용자 회원가입 정보 삽입 함수
// name: 닉네임/이름, username: ID
int db_signup(const char* name, const char* username, const char* pw) {
    char query[512];
    char escaped_name[ID_LEN * 2 + 1];
    char escaped_username[ID_LEN * 2 + 1];
    char escaped_pw[ID_LEN * 2 + 1];

    // 1. 비밀번호 해싱
    char hashed_pw[65];  // SHA-256은 64자 + 널문자
    hash_256_password(pw, hashed_pw);

    printf(" [DEBUG] db_signup 호출됨: name='%s', username='%s', pw='%s'\n", name, username, pw);
    printf(" [DEBUG] 해시된 비밀번호: %s\n", hashed_pw);  // 디버그용

    // 2. escape 시 해시된 pw 사용
    mysql_real_escape_string(conn, escaped_name, name, strlen(name));
    mysql_real_escape_string(conn, escaped_username, username, strlen(username));
    mysql_real_escape_string(conn, escaped_pw, hashed_pw, strlen(hashed_pw));

    // 3. 해시된 비밀번호를 쿼리에 삽입
    snprintf(query, sizeof(query),
        "INSERT INTO users (username, password, name, created_at, is_admin) "
        "VALUES('%s', '%s', '%s', NOW(), 0)", escaped_username, escaped_pw, escaped_name);

    printf(" [DEBUG] 생성된 SQL 쿼리: %s\n", query);

    pthread_mutex_lock(&mutex);
    if (mysql_query(conn, query)) {
        fprintf(stderr, " [ERROR] 회원가입 실패: %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    pthread_mutex_unlock(&mutex);
    printf(" [DEBUG] DB에 회원가입 정보 성공적으로 저장됨.\n");
    return 1;
}


// 이름 (name) 중복 여부를 DB에서 확인
int is_name_taken(const char* name) {
    char query[256];
    char escaped_name[ID_LEN * 2 + 1];
    mysql_real_escape_string(conn, escaped_name, name, strlen(name)); // 이스케이프 처리

    snprintf(query, sizeof(query), " SELECT name FROM users WHERE name = '%s'", escaped_name);
    pthread_mutex_lock(&mutex);
    if (mysql_query(conn, query)) {
        pthread_mutex_unlock(&mutex);
        fprintf(stderr, " 이름 중복 확인 쿼리 실패: %s\n", mysql_error(conn));
        return 1; // 쿼리 실패 시 중복으로 간주 (안전하게)
    }
    MYSQL_RES* res = mysql_store_result(conn);
    pthread_mutex_unlock(&mutex);
    if (!res) {
        fprintf(stderr, " 이름 중복 확인 결과 저장 실패: %s\n", mysql_error(conn));
        return 1; // 결과 가져오기 실패 시 중복으로 간주
    }
    int exists = mysql_num_rows(res) > 0;
    mysql_free_result(res);
    return exists;
}

// ID (username) 중복 여부를 DB에서 확인
int is_id_taken(const char* username) {
    char query[256];
    char escaped_username[ID_LEN * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username, strlen(username)); // 이스케이프 처리

    snprintf(query, sizeof(query), "SELECT username FROM users WHERE username = '%s'", escaped_username);
    pthread_mutex_lock(&mutex);
    if (mysql_query(conn, query)) {
        pthread_mutex_unlock(&mutex);
        fprintf(stderr, " ID 중복 확인 쿼리 실패: %s\n", mysql_error(conn));
        return 1; // 쿼리 실패 시 중복으로 간주 (안전하게)
    }
    MYSQL_RES* res = mysql_store_result(conn);
    pthread_mutex_unlock(&mutex);
    if (!res) {
        fprintf(stderr, " ID 중복 확인 결과 저장 실패: %s\n", mysql_error(conn));
        return 1; // 결과 가져오기 실패 시 중복으로 간주
    }
    int exists = mysql_num_rows(res) > 0;
    mysql_free_result(res);
    return exists;
}

// ID 유효성 검사 함수 (소문자+숫자, 8자 이상)
int is_valid_id(const char* id) {
    if (strlen(id) < 8) return 0; // 8자 미만

    int has_lower = 0;
    int has_digit = 0;

    for (int i = 0; id[i]; ++i) {
        if (islower(id[i])) has_lower = 1;
        else if (isdigit(id[i])) has_digit = 1;
        else return 0; // 소문자나 숫자가 아닌 문자가 있으면 실패
    }

    return has_lower && has_digit; // 둘 다 있어야 통과
}

// 비밀번호 유효성 검사 함수 (대소문자 포함, 8자 이상)
int is_valid_password(const char* pw) {
    int len = strlen(pw);
    int upper = 0;
    int lower = 0;
    int digit = 0; 

    if (len < 8) return 0; // 8자 미만

    for (int i = 0; i < len; ++i) {
        if (isupper(pw[i])) upper = 1;
        if (islower(pw[i])) lower = 1;
        if (isdigit(pw[i])) digit = 1;
    }
    // 대문자, 소문자, 숫자가 모두 포함되어야 함
    return upper && lower && digit; 
}

// 클라이언트로부터 회원가입 정보를 받고 DB에 저장하는 함수
int signup_user(int sock) {
    char name_input[ID_LEN], username_input[ID_LEN], pw_input[ID_LEN];

    // 이름 입력 및 유효성 검사 (길이 및 중복)
    while (1) {
        send_with_length(sock, " NEW 이름 입력 (2글자 이상) : ");
        if (!receive_message(sock, name_input)) {
            printf(" [DEBUG] signup_user: 이름 입력 중 클라이언트 연결 종료.\n");
            return 0; // 연결 종료 또는 오류
        }
        printf(" [DEBUG] 클라이언트로부터 이름 수신: '%s'\n", name_input); // 디버그 출력

        if (utf8_strlen(name_input) < 2) {
            send_with_length(sock, " 회원가입 실패 : 이름은 2글자 이상이어야 합니다.\n");
            printf(" [DEBUG] 이름 유효성 검사 실패 : 2글자 미만.\n"); // 디버그 출력
            continue; // 다시 이름 입력 요청
        }

        if (is_name_taken(name_input)) { // is_name_taken 내부에서 이스케이프 처리
            send_with_length(sock, " 회원가입 실패 : 이미 사용 중인 이름입니다.\n");
            printf(" [DEBUG] 이름 중복 검사 실패 : 이미 사용 중.\n"); // 디버그 출력
            continue; // 다시 이름 입력 요청
        }
        printf(" [DEBUG] 이름 유효성 검사 및 중복 확인 통과.\n"); // 디버그 출력
        break; // 유효한 이름이므로 루프 탈출
    }

    // ID 입력 및 유효성 검사 (기존 ID 중복 검사 포함)
    while (1) {
        send_with_length(sock, " NEW ID 입력 (소문자+숫자 8자 이상) : ");
        if (!receive_message(sock, username_input)) {
            printf(" [DEBUG] signup_user : ID 입력 중 클라이언트 연결 종료.\n");
            return 0;
        }
        printf(" [DEBUG] 클라이언트로부터 ID 수신: '%s'\n", username_input); // 디버그 출력

        if (!is_valid_id(username_input)) { // ID 유효성 검사
            send_with_length(sock, " 회원가입 실패 : ID는 소문자/숫자 조합 8자 이상이어야 합니다.\n");
            printf(" [DEBUG] ID 유효성 검사 실패: 형식 불일치.\n"); // 디버그 출력
            continue; // 다시 ID 입력 요청
        }

        if (is_id_taken(username_input)) { // is_id_taken 내부에서 이스케이프 처리
            send_with_length(sock, " 회원가입 실패: 이미 사용 중인 ID입니다.\n");
            printf(" [DEBUG] ID 중복 검사 실패: 이미 사용 중.\n"); // 디버그 출력
            continue; // 다시 ID 입력 요청
        }
        printf(" [DEBUG] ID 유효성 검사 및 중복 확인 통과.\n"); // 디버그 출력
        break; // 유효한 ID이므로 루프 탈출
    }

    // 비밀번호 입력 및 유효성 검사
    while (1) {
        send_with_length(sock, " NEW PW 입력 (대소문자, 숫자 포함 8자 이상): ");
        if (!receive_message(sock, pw_input)) {
            printf(" [DEBUG] signup_user: PW 입력 중 클라이언트 연결 종료.\n");
            return 0;
        }
        printf(" [DEBUG] 클라이언트로부터 PW 수신: '%s'\n", pw_input); // 디버그 출력

        if (!is_valid_password(pw_input)) { // 비밀번호 유효성 검사
            send_with_length(sock, " 회원가입 실패 : PW는 대소문자, 숫자를 포함한 8자 이상이어야 합니다.\n");
            printf(" [DEBUG] PW 유효성 검사 실패: 형식 불일치.\n"); // 디버그 출력
            continue; // 다시 PW 입력 요청
        }
        printf(" [DEBUG] PW 유효성 검사 통과.\n"); // 디버그 출력
        break; // 유효한 PW이므로 루프 탈출
    }

    // 모든 유효성 검사 통과 후 DB에 저장
    printf(" [DEBUG] 모든 회원가입 정보 유효성 검사 통과. DB 저장 시도.\n"); // 디버그 출력
    if (!db_signup(name_input, username_input, pw_input)) {
        send_with_length(sock, " 회원가입 실패 : 데이터베이스 저장 오류.\n");
        printf(" [DEBUG] db_signup 실패.\n"); // 디버그 출력
        return 0;
    }
    // 변경: 회원가입 성공 메시지 포맷팅을 클라이언트 파싱에 맞게 수정
    char success_msg[BUF_SIZE];
    snprintf(success_msg, sizeof(success_msg), " 회원가입 성공!\n");
    send_with_length(sock, success_msg);
    printf(" [DEBUG] 회원가입 성공 메시지 클라이언트에 전송 완료.\n"); // 디버그 출력
    return 1;
}


// DB에서 ID (username)/PW를 검증하여 로그인 성공 여부를 반환
// 로그인 함수
int db_login(const char* username, const char* pw) {
    char query[512];
    char escaped_username[ID_LEN * 2 + 1];
    char escaped_pw[ID_LEN * 2 + 1];

    //1. 입력된 비밀번호를 해시로 변환
    char hashed_pw[65];
    hash_256_password(pw, hashed_pw);

    //2. escape 처리 (해시된 pw 사용)
    mysql_real_escape_string(conn, escaped_username, username, strlen(username));
    mysql_real_escape_string(conn, escaped_pw, hashed_pw, strlen(hashed_pw));

    //3. 해시된 비밀번호로 SELECT 쿼리
    snprintf(query, sizeof(query),
        "SELECT * FROM users WHERE username='%s' AND password='%s'",
        escaped_username, escaped_pw);

    printf(" [DEBUG] 로그인 쿼리: %s\n", query);

    pthread_mutex_lock(&mutex);
    int result = mysql_query(conn, query);
    MYSQL_RES* res = mysql_store_result(conn);
    pthread_mutex_unlock(&mutex);

    if (!res) {
        fprintf(stderr, " [ERROR] 로그인 쿼리 실패: %s\n", mysql_error(conn));
        return 0;
    }

    int success = mysql_num_rows(res) > 0;
    mysql_free_result(res);

    if (success) {
        printf(" [DEBUG] 로그인 성공: %s\n", username);
    } else {
        printf(" [DEBUG] 로그인 실패: %s\n", username);
    }

    return success;
}
// DB에서 사용자 이름을 가져오는 함수
int db_get_name(const char* username, char* out_name_buf) {
    char query[256];
    char escaped_username[ID_LEN * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username, strlen(username)); // 이스케이프 처리

    snprintf(query, sizeof(query), "SELECT name FROM users WHERE username='%s'", escaped_username);
    pthread_mutex_lock(&mutex);
    if (mysql_query(conn, query)) {
        fprintf(stderr, " 이름 조회 쿼리 실패 : %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    MYSQL_RES* res = mysql_store_result(conn);
    pthread_mutex_unlock(&mutex);

    if (!res) {
        fprintf(stderr, " 이름 조회 결과 저장 실패 : %s\n", mysql_error(conn));
        return 0;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row && row[0]) {
        strncpy(out_name_buf, row[0], ID_LEN - 1);
        out_name_buf[ID_LEN - 1] = '\0';
        mysql_free_result(res);
        return 1;
    }
    mysql_free_result(res);
    return 0;
}

// 클라이언트로부터 로그인 정보(ID/PW)를 입력받아 로그인 처리
int login_user(int sock, char* out_username, char* out_name) {
    char pw_input[ID_LEN];

    send_with_length(sock, " ID : ");
    if (!receive_message(sock, out_username)) return 0;

    send_with_length(sock, " PW : ");
    if (!receive_message(sock, pw_input)) return 0;

    // db_login 함수 내에서 이미 이스케이프 처리하므로 여기서는 필요 없음
    if (!db_login(out_username, pw_input)) {
        send_with_length(sock, " 로그인 실패\n");
        return 0;
    }
    
    // 로그인 성공 시 사용자 이름(닉네임)도 가져와서 저장
    if (!db_get_name(out_username, out_name)) {
        fprintf(stderr, " 사용자 이름 가져오기 실패 : %s\n", out_username);
        send_with_length(sock, " 로그인 성공했지만, 사용자 정보를 불러올 수 없습니다.\n");
        return 0;
    }

    // 수정: 로그인 성공 메시지에 사용자 정보 포함
    char success_msg[BUF_SIZE];
    snprintf(success_msg, sizeof(success_msg), " 로그인 성공!%s:%s\n", out_username, out_name);
    send_with_length(sock, success_msg);
    return 1;
}

// 로그인한 사용자가 관리자 권한이 있는지 DB에서 조회
int db_is_admin(const char* username) {
    char query[256];
    char escaped_username[ID_LEN * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username, strlen(username)); // 이스케이프 처리

    snprintf(query, sizeof(query), " SELECT is_admin FROM users WHERE username='%s'", escaped_username);
    pthread_mutex_lock(&mutex);
    if (mysql_query(conn, query)) {
        fprintf(stderr, " 관리자 확인 쿼리 실패 : %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    MYSQL_RES* res = mysql_store_result(conn);
    pthread_mutex_unlock(&mutex);

    if (!res) {
        fprintf(stderr, " 관리자 확인 결과 저장 실패 : %s\n", mysql_error(conn));
        return 0;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    int admin = (row && atoi(row[0]) == 1);
    mysql_free_result(res);
    return admin;
}

// 소켓 번호로 clients[] 배열에서 해당 클라이언트 포인터 검색
Client* find_client_by_sock(int sock) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && clients[i]->sock == sock) {
            pthread_mutex_unlock(&mutex);
            return clients[i];
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

// ID (username)로 clients[] 배열에서 해당 클라이언트 포인터 검색
Client* find_client_by_id(const char* username) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && strcmp(clients[i]->username, username) == 0) {
            pthread_mutex_unlock(&mutex);
            return clients[i];
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

//이름(name)로 clients[] 배열에서 해당 클라이언트 포인터 검색
Client* find_client_by_name(const char* name) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && strcmp(clients[i]->name, name) == 0) {
            pthread_mutex_unlock(&mutex);
            return clients[i];
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

// 관리자가 대상 닉네임의 클라이언트를 강제로 접속 종료시키는 함수
void admin_kick(int sender_sock, const char* target_name) {
    Client* target_cli = find_client_by_name(target_name);
    if (target_cli) {
        send_with_length(target_cli->sock, " [서버] 관리자에 의해 추방되었습니다.\n");
        // 해당 소켓을 닫으면 receive_message에서 0을 반환하여 스레드 종료 유도
        close(target_cli->sock);
    } else {
        send_with_length(sender_sock, " [서버] 해당 ID의 사용자를 찾을 수 없습니다.\n");
    }
}

// 관리자가 대상 닉네임의 클라이언트를 채팅 금지 상태로 만드는 함수
void admin_mute(int sender_sock, const char* target_name) {
    Client* target_cli = find_client_by_name(target_name);
    if (target_cli) {
        pthread_mutex_lock(&mutex);
        target_cli->is_muted = 1;
        pthread_mutex_unlock(&mutex);
        send_with_length(target_cli->sock, " [서버] 음소거 되었습니다. 채팅할 수 없습니다.\n");
        send_with_length(sender_sock, " [서버] 사용자 음소거 완료.\n");
    } else {
        send_with_length(sender_sock, " [서버] 해당 ID의 사용자를 찾을 수 없습니다.\n");
    }
}

// 헬프 메시지를 클라이언트에게 전송하는 함수
void help_message(Client* cli) {
    char help_msg[BUF_SIZE * 2]; // 헬프 메시지는 길 수 있으므로 충분히 큰 버퍼를 할당

    // 기본 명령어 목록
    snprintf(help_msg, sizeof(help_msg), 
             "[서버] 사용 가능한 명령어:\n"
             "  /exit               : 전체 채팅방으로 이동합니다.\n"
             "  /w [대상ID] [메시지] : 특정 사용자에게 귓속말을 보냅니다.\n"
             "  /c [방이름]           : 방을 생성합니다.\n"
             "  /j [방이름]           : 방에 들어갑니다.\n"
             "  /l                   : 모든 방을 띄웁니다.\n"
             );
    
    // 관리자 명령어는 관리자에게만 표시
    if (cli->is_admin) {
        strncat(help_msg, 
                "  /kick [대상ID]       : 특정 사용자를 채팅방에서 강제로 내보냅니다.\n"
                "  /mute [대상ID]       : 특정 사용자의 채팅을 일시적으로 금지합니다.\n"
                "  /announce [메시지]   : 모든 접속자에게 공지 메시지를 보냅니다.\n",
                sizeof(help_msg) - strlen(help_msg) - 1);
    }
    // 공통 명령어 (항상 표시)
    strncat(help_msg, "  /help                : 모든 명령어 목록을 표시합니다.\n", sizeof(help_msg) - strlen(help_msg) - 1);

    // 클라이언트에게 헬프 메시지 전송
    send_with_length(cli->sock, help_msg);
}

// 관리자가 전체 클라이언트에게 공지 메시지를 전송하는 함수
void admin_announce(const char* msg) {
    pthread_mutex_lock(&mutex);
    char full_msg[BUF_SIZE];
    snprintf(full_msg, sizeof(full_msg), "[공지] %s\n", msg);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL) {
            send_with_length(clients[i]->sock, full_msg);
        }
    }
    pthread_mutex_unlock(&mutex);
}

// 클라이언트의 ID (username)를 변경하고 DB 반영
// 클라이언트의 ID (username)를 변경하고 DB 반영
int change_id(int client_sock, const char* old_username, char* out_new_username) {
    char new_username[ID_LEN];

    send_with_length(client_sock, " 새 ID 입력 (소문자+숫자 8자 이상) : ");
    if (!receive_message(client_sock, new_username)) {
        printf(" [DEBUG] change_id : 클라이언트 응답 없음\n");
        return 0;
    }

    printf(" [DEBUG] change_id : 입력받은 새 ID = '%s', 길이 = %d\n", new_username, (int)strlen(new_username));

    if (strlen(new_username) == 0) {
        send_with_length(client_sock, " ID가 비어있습니다.\n");
        printf(" [DEBUG] change_id : ID가 비어있음\n");
        return 0;
    }

    // ID 유효성 검사 추가
    if (!is_valid_id(new_username)) {
        send_with_length(client_sock, " ID 변경 실패: ID는 소문자/숫자 조합 8자 이상이어야 합니다.\n");
        printf(" [DEBUG] change_id : ID 유효성 검사 실패 = '%s'\n", new_username);
        return 0;
    }
    printf(" [DEBUG] change_id : ID 유효성 검사 통과\n");

    if (is_id_taken(new_username)) { // is_id_taken 내부에서 이스케이프 처리
        send_with_length(client_sock, " 이미 사용 중인 ID입니다.\n");
        printf(" [DEBUG] change_id : ID 중복 = '%s'\n", new_username);
        return 0;
    }
    printf(" [DEBUG] change_id : ID 중복 검사 통과\n");

    char query[256];
    char escaped_new_username[ID_LEN * 2 + 1];
    char escaped_old_username[ID_LEN * 2 + 1];

    mysql_real_escape_string(conn, escaped_new_username, new_username, strlen(new_username)); // 이스케이프 처리
    mysql_real_escape_string(conn, escaped_old_username, old_username, strlen(old_username)); // 이스케이프 처리

    snprintf(query, sizeof(query), " UPDATE users SET username='%s' WHERE username='%s'", escaped_new_username, escaped_old_username);
    printf(" [DEBUG] change_id : 실행할 쿼리 = '%s'\n", query);

    pthread_mutex_lock(&mutex);
    int result = mysql_query(conn, query);
    pthread_mutex_unlock(&mutex);

    if (result == 0) {
        send_with_length(client_sock, " ID 변경 완료\n");
        printf(" [DEBUG] change_id : ID 변경 성공: %s -> %s\n", old_username, new_username);
        strncpy(out_new_username, new_username, ID_LEN - 1);
        out_new_username[ID_LEN - 1] = '\0';
        return 1;
    } else {
        send_with_length(client_sock, " ID 변경 실패\n");
        printf(" [DEBUG] change_id : ID 변경 실패 : %s\n", mysql_error(conn));
        return 0;
    }
}

// 클라이언트의 비밀번호를 변경하고 DB 반영 (Prepared Statement 적용)
// 성공 시 1 반환, 실패 시 0 반환
int change_pw(int client_sock, const char* username) {
    char new_pw[ID_LEN];          // 사용자로부터 받은 새 비밀번호
    char hashed_pw[65];           // 해시된 비밀번호 (SHA-256은 64자 + 널)
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[2];

    send_with_length(client_sock, " 새 비밀번호를 입력하세요 (8자 이상, 대소문자+숫자 포함): > ");
    if (!receive_message(client_sock, new_pw)) {
        printf(" [서버] PW 변경 - 클라이언트 응답 없음 (소켓 %d)\n", client_sock);
        return 0;
    }

    if (!is_valid_password(new_pw)) {
        send_with_length(client_sock, " [서버] 비밀번호는 8자 이상이며, 대소문자와 숫자를 포함해야 합니다.\n");
        return 0;
    }

    printf(" [서버] PW 변경 시도 : 사용자 %s\n", username);

    // 새 비밀번호 해싱
    hash_256_password(new_pw, hashed_pw);
    printf(" [DEBUG] 해시된 비밀번호: %s\n", hashed_pw); // 선택적 디버깅

    pthread_mutex_lock(&mutex);

    stmt = mysql_stmt_init(conn);
    if (!stmt) {
        fprintf(stderr, " [DB] mysql_stmt_init() failed : %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    const char *query = "UPDATE users SET password = ? WHERE username = ?";
    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, " [DB] mysql_stmt_prepare() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    memset(bind, 0, sizeof(bind));

    unsigned long pw_len = strlen(hashed_pw);
    unsigned long user_len = strlen(username);

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char*)hashed_pw;
    bind[0].length = &pw_len;

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char*)username;
    bind[1].length = &user_len;

    if (mysql_stmt_bind_param(stmt, bind)) {
        fprintf(stderr, " [DB] mysql_stmt_bind_param() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, " [DB] mysql_stmt_execute() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    if (mysql_stmt_affected_rows(stmt) > 0) {
        send_with_length(client_sock, " 비밀번호 변경이 완료되었습니다.\n");
        printf(" [서버] PW 변경 성공: %s\n", username);
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 1;
    } else {
        send_with_length(client_sock, " 비밀번호 변경 실패. (사용자를 찾을 수 없거나 동일한 비밀번호)\n");
        printf(" [서버] PW 변경 실패 : %s (영향 받은 행 없음)\n", username);
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }
}

// 사용자의 닉네임(name)을 변경하는 함수
int db_change_name(const char* user_id, const char* new_name) {
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[3]; // new_name, user_id
    int result = 0;
    char query[BUF_SIZE];
    unsigned long new_name_len, user_id_len;

    // 새 닉네임 길이 검사 (유효성 검사는 호출하는 곳에서 하는 것이 일반적)
    // 여기서는 단순히 길이만 확인
    if (utf8_strlen(new_name) < 2 || utf8_strlen(new_name) > 10) { // 닉네임 길이 제한 (예: 2~10자)
        printf(" [DB] 닉네임 길이 유효성 검사 실패 : %s\n", new_name);
        return 0; // 유효성 검사 실패
    }

    pthread_mutex_lock(&mutex); // DB 접근 뮤텍스 잠금

    // Prepare statement로 SQL 인젝션 방지
    snprintf(query, BUF_SIZE, " UPDATE users SET name = ? WHERE username = ?");
    stmt = mysql_stmt_init(conn);
    if (!stmt) {
        fprintf(stderr, " [DB] mysql_stmt_init() failed : %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, " [DB] mysql_stmt_prepare() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    // 바인딩 파라미터 초기화
    memset(bind, 0, sizeof(bind));

    // new_name 바인딩
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char*)new_name;
    new_name_len = strlen(new_name);
    bind[0].length = &new_name_len;

    // user_id 바인딩
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char*)user_id;
    user_id_len = strlen(user_id);
    bind[1].length = &user_id_len;

    if (mysql_stmt_bind_param(stmt, bind)) {
        fprintf(stderr, " [DB] mysql_stmt_bind_param() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, " [DB] mysql_stmt_execute() failed : %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        pthread_mutex_unlock(&mutex);
        return 0;
    }

    if (mysql_stmt_affected_rows(stmt) > 0) {
        result = 1; // 성공
    } else {
        printf(" [DB] 닉네임 변경 실패 : %s -> %s (영향 받은 행 없음)\n", user_id, new_name);
    }

    mysql_stmt_close(stmt);
    pthread_mutex_unlock(&mutex); // DB 접근 뮤텍스 해제
    return result;
}


// 사용자 ID (username)에 해당하는 레코드를 users 테이블에서 삭제하는 함수
int delete_user(const char* username) {
    char query[256];
    char escaped_username[ID_LEN * 2 + 1];
    mysql_real_escape_string(conn, escaped_username, username, strlen(username)); // 이스케이프 처리

    snprintf(query, sizeof(query), " DELETE FROM users WHERE username = '%s'", escaped_username);

    pthread_mutex_lock(&mutex);
    int result = mysql_query(conn, query);
    pthread_mutex_unlock(&mutex);

    if (result == 0) {
        printf(" [서버] 사용자 삭제 성공 : %s\n", username);
        return 1;
    } else {
        printf(" [서버] 사용자 삭제 실패 : %s\n", mysql_error(conn));
        return 0;
    }
}

void broadcast_to_room(const char* roomname, const char* msg, int except_sock) {
    pthread_mutex_lock(&mutex);
    
    printf(" [DEBUG] broadcast_to_room: 방 = '%s', 메시지 = '%s', 제외소켓 = %d\n", roomname, msg, except_sock);
    
    int sent_count = 0;
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] && strcmp(clients[i]->room, roomname) == 0 && clients[i]->sock != except_sock) {
            printf(" [DEBUG] 메시지 전송 : %s(%s)에게 전송\n", clients[i]->name, clients[i]->username);
            send_with_length(clients[i]->sock, msg);
            sent_count++;
        }
    }
    
    printf(" [DEBUG] 총 %d명에게 메시지 전송 완료\n", sent_count);
    pthread_mutex_unlock(&mutex);
}



// 귓속말 전송
void whisper(const char *from_name, const char *to_name, const char *body, int sender_sock) {
    char fmt[BUF_SIZE];
    char time_str[16];  // 추가
    Client* target_cli = find_client_by_name(to_name); 

    // 현재 시간 가져오기 (추가)
    get_current_time(time_str);

    if (target_cli == NULL || target_cli->room[0] == '\0') { 
        char not_found_msg[BUF_SIZE];
        snprintf(not_found_msg, sizeof(not_found_msg), " [서버] '%s'님을 찾을 수 없습니다. (현재 접속 중인 사용자가 아니거나 ID가 다릅니다.)\n", to_name);
        send_with_length(sender_sock, not_found_msg);
    } else {
        // 시간 포함으로 수정
        snprintf(fmt, sizeof(fmt), "%s [귓속말] %s → %s: %s\n", time_str, from_name, to_name, body);
        send_with_length(target_cli->sock, fmt);
    }
}

int save_chat_log(const char* sender, const char* room, const char* message, 
                  int is_whisper, const char* recipients) {
    char query[2048];
    char escaped_sender[ID_LEN * 2 + 1];
    char escaped_room[ID_LEN * 2 + 1];
    char escaped_message[BUF_SIZE * 2 + 1];
    char escaped_recipients[300]; // recipients 길이의 2배 + 1

    // SQL 인젝션 방지를 위한 이스케이프 처리
    mysql_real_escape_string(conn, escaped_sender, sender, strlen(sender));
    mysql_real_escape_string(conn, escaped_message, message, strlen(message));
    
    // room과 recipients는 NULL일 수 있음
    if (room) {
        mysql_real_escape_string(conn, escaped_room, room, strlen(room));
    }
    if (recipients) {
        mysql_real_escape_string(conn, escaped_recipients, recipients, strlen(recipients));
    }

    // 쿼리 작성
    if (room && recipients) {
        // 방과 수신자 모두 있는 경우
        snprintf(query, sizeof(query),
            "INSERT INTO chat_logs (sender, room, message, is_whisper, recipients, created_at) "
            "VALUES('%s', '%s', '%s', %d, '%s', NOW())", 
            escaped_sender, escaped_room, escaped_message, is_whisper, escaped_recipients);
    } else if (room) {
        // 방만 있는 경우 (전체 채팅)
        snprintf(query, sizeof(query),
            "INSERT INTO chat_logs (sender, room, message, is_whisper, recipients, created_at) "
            "VALUES('%s', '%s', '%s', %d, NULL, NOW())", 
            escaped_sender, escaped_room, escaped_message, is_whisper);
    } else if (recipients) {
        // 수신자만 있는 경우 (귓속말)
        snprintf(query, sizeof(query),
            "INSERT INTO chat_logs (sender, room, message, is_whisper, recipients, created_at) "
            "VALUES('%s', NULL, '%s', %d, '%s', NOW())", 
            escaped_sender, escaped_message, is_whisper, escaped_recipients);
    } else {
        // 둘 다 없는 경우 (전체 채팅, 방 없음)
        snprintf(query, sizeof(query),
            "INSERT INTO chat_logs (sender, room, message, is_whisper, recipients, created_at) "
            "VALUES('%s', NULL, '%s', %d, NULL, NOW())", 
            escaped_sender, escaped_message, is_whisper);
    }

    pthread_mutex_lock(&mutex);
    int result = mysql_query(conn, query);
    if (result != 0) {
        fprintf(stderr, " 채팅 로그 저장 실패 : %s\n", mysql_error(conn));
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    pthread_mutex_unlock(&mutex);
    
    printf(" [DB LOG] 채팅 저장됨 - 보낸이 : %s, 귓속말 : %s, 수신자 : %s\n", 
           sender, is_whisper ? "YES" : "NO", recipients ? recipients : "ALL");
    return 1;
}

//방 생성 함수
void handle_create_room(Client* cli, const char* roomname) {
    for (int i = 0; i < room_count; i++) {
        if (strcmp(chat_rooms[i].name, roomname) == 0) {
            send_with_length(cli->sock, " [서버] 이미 존재하는 방입니다.\n");
            return;
        }
    }

    if (room_count >= MAX_ROOMS) {
        send_with_length(cli->sock, " [서버] 방 개수 제한 초과입니다.\n");
        return;
    }

    pthread_mutex_lock(&mutex);
    strncpy(chat_rooms[room_count].name, roomname, ID_LEN - 1);
    chat_rooms[room_count].member_count = 0;
    room_count++;
    pthread_mutex_unlock(&mutex);

    send_with_length(cli->sock, " [서버] 방이 생성되었습니다. /j 방이름 으로 입장하세요.\n");
}

//채팅방에 입장하는 함수
void handle_join_room(Client* cli, const char* roomname) {
    int found = 0;
    int room_index = -1;
    
    // 방 찾기
    for (int i = 0; i < room_count; i++) {
        if (strcmp(chat_rooms[i].name, roomname) == 0) {
            found = 1;
            room_index = i;
            break;
        }
    }

    if (!found) {
        send_with_length(cli->sock, " [서버] 존재하지 않는 방입니다.\n");
        return;
    }

    pthread_mutex_lock(&mutex);
    
    // 현재 방 정보 저장
    char previous_room[ID_LEN];
    strncpy(previous_room, cli->room, ID_LEN - 1);
    previous_room[ID_LEN - 1] = '\0';
    
    // 이전 방에서 나가기 (멤버 수 감소)
    if (strlen(previous_room) > 0 && strcmp(previous_room, "ALL") != 0) {
        for (int i = 0; i < room_count; i++) {
            if (strcmp(chat_rooms[i].name, previous_room) == 0) {
                if (chat_rooms[i].member_count > 0) {
                    chat_rooms[i].member_count--;
                }
                break;
            }
        }
    }
    
    // 새 방에 입장
    strncpy(cli->room, roomname, ID_LEN - 1);
    cli->room[ID_LEN - 1] = '\0';
    
    // 새 방의 멤버 수 증가
    chat_rooms[room_index].member_count++;
    
    pthread_mutex_unlock(&mutex);

    // 이전 방에서 나가는 메시지 (ALL이 아닌 경우만)
    if (strlen(previous_room) > 0 && strcmp(previous_room, "ALL") != 0) {
        char leave_msg[BUF_SIZE];
        snprintf(leave_msg, sizeof(leave_msg), "[서버] %s님이 '%s' 방을 나갔습니다.\n", cli->name, previous_room);
        broadcast_to_room(previous_room, leave_msg, cli->sock);
    }
    
    // 새 방에 입장 메시지
    char enter_msg[BUF_SIZE];
    snprintf(enter_msg, sizeof(enter_msg), "[서버] %s님이 '%s' 방에 입장했습니다.\n", cli->name, roomname);
    broadcast_to_room(roomname, enter_msg, cli->sock);

    // 클라이언트에게 성공 메시지
    char success_msg[BUF_SIZE];
    snprintf(success_msg, sizeof(success_msg), "[서버] '%s' 방에 입장했습니다.\n", roomname);
    send_with_length(cli->sock, success_msg);
}

//채팅방 나가기 /exit
int handle_leave_room(Client* cli) {
    pthread_mutex_lock(&mutex);
    
    if (strlen(cli->room) == 0 || strcmp(cli->room, "ALL") == 0) {
        // 전체 채팅방에서 나가기 - 채팅 종료
        cli->room[0] = '\0';  // 방 정보 초기화
        pthread_mutex_unlock(&mutex);
        send_with_length(cli->sock, " [서버] 채팅을 종료하고 전체 채팅으로 돌아갑니다.\n");
        return 1; // 메인 메뉴로 돌아가기
    } else {
        // 특정 방에서 나가기
        char leave_msg[BUF_SIZE];
        snprintf(leave_msg, sizeof(leave_msg), " [서버] %s님이 '%s' 방을 나갔습니다.\n", cli->name, cli->room);
        
        // 현재 방의 멤버 수 감소
        for (int i = 0; i < room_count; i++) {
            if (strcmp(chat_rooms[i].name, cli->room) == 0) {
                if (chat_rooms[i].member_count > 0) {
                    chat_rooms[i].member_count--;
                }
                break;
            }
        }
        
        // 방을 나가는 메시지를 현재 방에 브로드캐스트
        broadcast_to_room(cli->room, leave_msg, cli->sock);
        
        // 전체 채팅방으로 이동
        strncpy(cli->room, "ALL", ID_LEN - 1);
        cli->room[ID_LEN - 1] = '\0';
        pthread_mutex_unlock(&mutex);

        send_with_length(cli->sock, " [서버] 전체 채팅방으로 이동했습니다. 계속 채팅하거나 /exit로 메인 메뉴로 이동하세요.\n");
        return 0; // 채팅 루프 계속
    }
}

void cleanup_client_room(Client* cli) {
    if (cli && strlen(cli->room) > 0 && strcmp(cli->room, "ALL") != 0) {
        pthread_mutex_lock(&mutex);
        for (int i = 0; i < room_count; i++) {
            if (strcmp(chat_rooms[i].name, cli->room) == 0) {
                if (chat_rooms[i].member_count > 0) {
                    chat_rooms[i].member_count--;
                }
                break;
            }
        }
        pthread_mutex_unlock(&mutex);
    }
}

// 현재 방 목록을 클라이언트에게 전송하는 함수
void handle_list_rooms(Client* cli) {
    char msg[BUF_SIZE] = " [서버] 현재 방 목록 : \n";
    for (int i = 0; i < room_count; i++) {
        char line[100];
        snprintf(line, sizeof(line), "  - %s (%d명)\n", chat_rooms[i].name, chat_rooms[i].member_count);
        strncat(msg, line, sizeof(msg) - strlen(msg) - 1);
    }
    send_with_length(cli->sock, msg);
}


// 클라이언트 처리 및 채팅 세션 통합 함수
void* chat_session(void *arg) {
   Client *cli = (Client*)arg;
   int sock = cli->sock;
   char input_buf[BUF_SIZE]; // 사용자 입력 버퍼
   char msg_buf[BUF_SIZE];   // 채팅 메시지 버퍼

   printf(" [서버] 새로운 클라이언트 연결 : %s (소켓 %d)\n", cli->username, sock);

   // 전체 세션을 감싸는 루프 (로그아웃 시 다시 로그인 메뉴로)
   while (1) {
       // 클라이언트 정보 초기화 (로그아웃 후 재로그인을 위해)
       pthread_mutex_lock(&mutex);
       cli->is_admin = 0;
       cli->is_muted = 0;
       cli->room[0] = '\0';
       // username과 name을 임시값으로 재설정
       snprintf(cli->username, ID_LEN - 1, " Guest%d", sock);
       cli->username[ID_LEN - 1] = '\0';
       snprintf(cli->name, ID_LEN - 1, " 게스트%d", sock);
       cli->name[ID_LEN - 1] = '\0';
       pthread_mutex_unlock(&mutex);

       // ------------------- 1. 초기 로그인/회원가입 메뉴 -------------------
       int logged_in = 0;
       while (!logged_in) {
           send_with_length(sock, "--------------------------------------------------------------------\n\n");
           send_with_length(sock, "                    1.회원가입 2.로그인 3. 종료 \n\n");
           send_with_length(sock, "--------------------------------------------------------------------\n\n");
           send_with_length(sock, " 입력 >> ");
           if (!receive_message(sock, input_buf)) {
               printf(" [서버] 클라이언트(%s) 연결 종료 (초기 메뉴).\n", cli->username);
               goto cleanup; // 연결 끊김
           }
       
           if (strcmp(input_buf, "1") == 0) { // 회원가입
               if (!signup_user(sock)) {
                   // signup_user 내부에서 이미 메시지를 보냄
               }
               continue;
           } else if (strcmp(input_buf, "2") == 0) { // 로그인
               if (!login_user(sock, cli->username, cli->name)) {
                   continue;
               }
               // 로그인 성공 시, cli 구조체에 ID와 관리자 권한 업데이트
               cli->is_admin = db_is_admin(cli->username);
               if (cli->is_admin) {
                   send_with_length(sock, " 관리자님 어서오세요!\n");
               }
               logged_in = 1; // 로그인 성공
               printf(" [서버] 클라이언트 %s(%s) 로그인 성공 (소켓 %d)\n", cli->name, cli->username, sock);
               break; // 로그인 성공, 다음 메뉴로 이동
           } else if (strcmp(input_buf, "3") == 0) { // 종료
               send_with_length(sock, " 정말로 종료하시겠습니까? (y/n) > ");
               
               if (!receive_message(sock, input_buf)) {
                   printf(" [서버] 클라이언트(%s) 연결 종료 (종료 확인 중).\n", cli->username);
                   goto cleanup;
               }
               
               if (strcmp(input_buf, "y") == 0 || strcmp(input_buf, "Y") == 0) {
                   send_with_length(sock, " 서버 연결을 종료합니다.\n");
                   sleep(1);
                   shutdown(sock, SHUT_WR);
                   goto cleanup;
               } else if (strcmp(input_buf, "n") == 0 || strcmp(input_buf, "N") == 0) {
                   send_with_length(sock, " 서버 연결 종료를 취소합니다.\n");
                   continue;
               } else {
                   send_with_length(sock, " 잘못된 입력입니다. 종료를 취소합니다.\n");
                   continue;
               }
           } else {
               send_with_length(sock, " 잘못된 입력입니다. 다시 시도하세요.\n");
           }
       }

       // ------------------- 2. 메인 메뉴 루프 -------------------
       int logout_requested = 0;
       while (!logout_requested) {
           send_with_length(sock, "\033[2J\033[1;1H");
           send_with_length(sock, "--------------------------------------------------------------------\n ");
           send_with_length(sock, "                          [메인 메뉴]\n");
           send_with_length(sock, "--------------------------------------------------------------------\n\n");
           send_with_length(sock, "             1. 개인정보 변경 2. 채팅 시작 3. 로그아웃\n\n");
           send_with_length(sock, "--------------------------------------------------------------------\n\n");
           send_with_length(sock, " 입력 >> ");
           if (!receive_message(sock, input_buf)) {
               printf(" [서버] 클라이언트(%s) 연결 종료 (메인 메뉴).\n", cli->username);
               goto cleanup;
           }

           if (strcmp(input_buf, "1") == 0) { // 개인정보 변경 서브 메뉴
               send_with_length(sock, "\033[2J\033[1;1H"); // 화면 클리어 추가
               while (1) {
                   send_with_length(sock, "--------------------------------------------------------------------\n ");
                   send_with_length(sock, "                         [개인정보 변경]\n");
                   send_with_length(sock, "--------------------------------------------------------------------\n\n");
                   send_with_length(sock, " 1. ID 변경 2. 비밀번호 변경 3. 닉네임 변경 4. 회원탈퇴 5. 돌아가기\n\n");
                   send_with_length(sock, "--------------------------------------------------------------------\n\n");
                   send_with_length(sock, " 입력 >> ");
                   if (!receive_message(sock, input_buf)) {
                       printf(" [서버] 클라이언트(%s) 연결 종료 (개인정보 변경 서브 메뉴).\n", cli->username);
                       goto cleanup;
                   }
               
                   if (strcmp(input_buf, "1") == 0) { // ID 변경
                       send_with_length(sock, " ID 변경을 하시겠습니까? (y/n)\n> ");
                       usleep(50000);
                       if (!receive_message(sock, input_buf)) {
                           printf(" [서버] 클라이언트(%s) 연결 종료 (ID 변경 확인).\n", cli->username);
                           goto cleanup;
                       }

                       if (strcmp(input_buf, "Y") == 0 || strcmp(input_buf, "y") == 0) {
                           char new_username[ID_LEN];
                           if (change_id(sock, cli->username, new_username)) {
                               pthread_mutex_lock(&mutex);
                               strncpy(cli->username, new_username, ID_LEN - 1);
                               cli->username[ID_LEN - 1] = '\0';
                               pthread_mutex_unlock(&mutex);
                               send_with_length(sock, " ID가 변경되었습니다.\n");
                           }
                       } else if (strcmp(input_buf, "N") == 0 || strcmp(input_buf, "n") == 0) {
                           send_with_length(sock, " ID 변경을 취소합니다.\n");
                       } else {
                           send_with_length(sock, " 잘못된 입력입니다. Y 또는 N을 입력해주세요.\n");
                       }

                   } else if (strcmp(input_buf, "2") == 0) { // 비밀번호 변경
                       send_with_length(sock, " PW 변경을 하시겠습니까? (y/n)\n> ");
                       usleep(50000);
                       if (!receive_message(sock, input_buf)) {
                           printf(" [서버] 클라이언트(%s) 연결 종료 (PW 변경 확인).\n", cli->username);
                           goto cleanup;
                       }

                       if (strcmp(input_buf, "Y") == 0 || strcmp(input_buf, "y") == 0) {
                           if (change_pw(sock, cli->username)) {
                               send_with_length(sock, " 비밀번호가 변경되었습니다.\n");
                           }
                       } else if (strcmp(input_buf, "N") == 0 || strcmp(input_buf, "n") == 0) {
                           send_with_length(sock, " PW 변경을 취소합니다.\n");
                       } else {
                           send_with_length(sock, " 잘못된 입력입니다. Y 또는 N을 입력해주세요.\n");
                       }

                   } else if (strcmp(input_buf, "3") == 0) { // 닉네임 변경
                       send_with_length(sock, " 닉네임 변경을 하시겠습니까? (y/n)\n> ");
                       usleep(50000);
                       if (!receive_message(sock, input_buf)) {
                           printf(" [서버] 클라이언트(%s) 연결 종료 (닉네임 변경 확인).\n", cli->username);
                           goto cleanup;
                       }

                       if (strcmp(input_buf, "Y") == 0 || strcmp(input_buf, "y") == 0) {
                           char new_name[ID_LEN];
                           char confirm_msg[BUF_SIZE];
                           send_with_length(sock, " 새 닉네임을 입력하세요 (2~10자, 한글/영어/숫자) : ");
                           if (!receive_message(sock, new_name)) {
                               printf(" [서버] 클라이언트(%s) 연결 종료 (닉네임 변경 입력).\n", cli->username);
                               goto cleanup;
                           }
                       
                           if (utf8_strlen(new_name) < 2 || utf8_strlen(new_name) > 10) {
                               send_with_length(sock, " [서버] 닉네임은 2자 이상 10자 이하로 입력해주세요.\n");
                           }
                           else if (is_name_taken(new_name)) {
                               send_with_length(sock, " [서버] 이미 사용 중인 닉네임입니다.\n");
                           }
                           else if (db_change_name(cli->username, new_name)) {
                               pthread_mutex_lock(&mutex);
                               strncpy(cli->name, new_name, ID_LEN - 1);
                               cli->name[ID_LEN - 1] = '\0';
                               pthread_mutex_unlock(&mutex);
                               snprintf(confirm_msg, BUF_SIZE, " 닉네임이 '%s'(으)로 변경되었습니다.\n", cli->name);
                               send_with_length(sock, confirm_msg);
                           } else {
                               send_with_length(sock, " 닉네임 변경 실패. 다시 시도해주세요.\n");
                           }
                       } else if (strcmp(input_buf, "N") == 0 || strcmp(input_buf, "n") == 0) {
                           send_with_length(sock, " 닉네임 변경을 취소합니다.\n");
                       } else {
                           send_with_length(sock, " 잘못된 입력입니다. Y 또는 N을 입력해주세요.\n");
                       }

                   } else if (strcmp(input_buf, "4") == 0) { // 회원 탈퇴
                       send_with_length(sock, " 정말로 회원 탈퇴하시겠습니까? (y/n) > ");
                       if (!receive_message(sock, input_buf)) {
                           printf(" [서버] 클라이언트(%s) 연결 종료 (회원탈퇴 확인).\n", cli->username);
                           goto cleanup;
                       }
                       if (strcmp(input_buf, "y") == 0 || strcmp(input_buf, "Y") == 0) {
                           if (delete_user(cli->username)) {
                               send_with_length(sock, " 회원 탈퇴가 완료되었습니다. 서버 연결을 종료합니다.\n");
                               sleep(1);
                               shutdown(sock, SHUT_WR);
                               goto cleanup;
                           } else {
                               send_with_length(sock, " 회원 탈퇴 실패.\n");
                           }
                       } else {
                           send_with_length(sock, " 회원 탈퇴를 취소합니다.\n");
                       }
                   } else if (strcmp(input_buf, "5") == 0) { // 돌아가기
                       send_with_length(sock, " 메인 메뉴로 돌아갑니다.\n");
                       break;
                   } else {
                       send_with_length(sock, " 잘못된 입력입니다. 다시 선택해주세요.\n");
                   }
               }
           } else if (strcmp(input_buf, "2") == 0) { // 채팅 시작
               send_with_length(sock, "\033[2J\033[1;1H"); // 화면 클리어 추가
               pthread_mutex_lock(&mutex);
               strncpy(cli->room, "ALL", ID_LEN - 1);  // 전체방 자동 진입
               cli->room[ID_LEN - 1] = '\0';           // 널 종료 확실히
               pthread_mutex_unlock(&mutex);

               send_with_length(cli->sock, " 채팅을 시작합니다. /help 입력시 명령어 호출\n");

               char enter_msg[BUF_SIZE];
               snprintf(enter_msg, sizeof(enter_msg), " [서버] %s님이 채팅방에 입장했습니다.\n", cli->name);
               broadcast_to_room("ALL", enter_msg, sock);

               printf(" [DEBUG] 채팅 시작: %s(%s)이 '%s' 방에 입장\n", cli->name, cli->username, cli->room);

               // 채팅 루프
               while (1) {
                   if (!receive_message(sock, msg_buf)) {
                       printf(" [서버] 클라이언트(%s) 연결 종료 (채팅 중).\n", cli->username);
                       goto cleanup;
                   }

                       // 음소거 체크
                   if (cli->is_muted) {
                       send_with_length(sock, " [서버] 음소거 상태에서는 채팅할 수 없습니다.\n");
                       continue;
                   }

                   printf(" [DEBUG] 메시지 수신: %s(%s) in '%s': %s\n", cli->name, cli->username, cli->room, msg_buf);

                   // === /exit 처리 ===
                   if (strcmp(msg_buf, "/exit") == 0) {
                        int should_exit = handle_leave_room(cli);
                        if (should_exit)
                            break;    // 메인 메뉴로 이동
                        continue;      // 전체 채팅방으로 이동 후 채팅 계속
                    }
                   // === 기타 명령 ===
                   else if (strncmp(msg_buf, "/c ", 3) == 0) {
                       handle_create_room(cli, msg_buf + 3);
                   } else if (strncmp(msg_buf, "/j ", 3) == 0) {
                       handle_join_room(cli, msg_buf + 3);
                   }else if (strcmp(msg_buf, "/help") == 0){
                       help_message(cli);
                   }else if (strcmp(msg_buf, "/l") == 0) {
                       handle_list_rooms(cli);
                   } else if (strncmp(msg_buf, "/w ", 3) == 0) {
                       char *p = msg_buf + 3;
                       char target_username[ID_LEN], body[BUF_SIZE];
                       if (sscanf(p, "%49s %1023[^\n]", target_username, body) >= 2) {
                           target_username[strcspn(target_username, "\n ")] = '\0';
                           body[strcspn(body, "\n")] = '\0';
                           whisper(cli->username, target_username, body, sock);
                           save_chat_log(cli->username, NULL, body, 1, target_username);
                       } else {
                           send_with_length(sock, " 사용법 : /w 대상ID 메시지\n");
                       }
                   } else if (strncmp(msg_buf, "/kick ", 6) == 0) {
                       if (cli->is_admin) {
                           char target_username_kick[ID_LEN];
                           strncpy(target_username_kick, msg_buf + 6, ID_LEN - 1);
                           target_username_kick[ID_LEN - 1] = '\0';
                           target_username_kick[strcspn(target_username_kick, "\n ")] = '\0';
                           admin_kick(sock, target_username_kick);
                           save_chat_log(cli->username, NULL, msg_buf, 0, NULL);
                       } else {
                           send_with_length(sock, " [서버] 관리자만 사용 가능한 명령어입니다.\n");
                       }
                   } else if (strncmp(msg_buf, "/mute ", 6) == 0) {
                       if (cli->is_admin) {
                           char target_username_mute[ID_LEN];
                           strncpy(target_username_mute, msg_buf + 6, ID_LEN - 1);
                           target_username_mute[ID_LEN - 1] = '\0';
                           target_username_mute[strcspn(target_username_mute, "\n ")] = '\0';
                           admin_mute(sock, target_username_mute);
                           save_chat_log(cli->username, NULL, msg_buf, 0, NULL);
                       } else {
                           send_with_length(sock, " [서버] 관리자만 사용 가능한 명령어입니다.\n");
                       }
                   } else if (strncmp(msg_buf, "/announce ", 10) == 0) {
                       if (cli->is_admin) {
                           admin_announce(msg_buf + 10);
                           save_chat_log(cli->username, NULL, msg_buf, 0, NULL);
                       } else {
                           send_with_length(sock, " [서버] 관리자만 사용 가능한 명령어입니다.\n");
                       }
                   } else {
                       // 일반 메시지
                       if (strlen(cli->room) == 0) {
                           send_with_length(sock, "      [서버] 먼저 채팅방에 입장하세요. /r로 목록 확인 후 /j 방이름 으로 입장.\n");
                       } else {
                           char time_str[16];  // 추가
                           get_current_time(time_str);  // 추가
                           char formatted_msg[BUF_SIZE]; 
                           // 시간 포함으로 수정
                           snprintf(formatted_msg, sizeof(formatted_msg), "%s [%s] %s\n",
                                       time_str, cli->name, msg_buf);
                           broadcast_to_room(cli->room, formatted_msg, sock);
                           save_chat_log(cli->username, cli->room, msg_buf, 0, NULL);  // 추가
                       }
                   }
               }
               char exit_msg[BUF_SIZE];
               snprintf(exit_msg, sizeof(exit_msg), " [서버] %s님이 채팅을 종료했습니다.\n", cli->name);
               broadcast_to_room("ALL", exit_msg, sock);
           } else if (strcmp(input_buf, "3") == 0) { // 로그아웃
               send_with_length(sock, "\033[2J\033[1;1H"); // 화면 클리어 추가
               send_with_length(sock, " 로그아웃을 하시겠습니까? (y/n)\n> ");
               if (!receive_message(sock, input_buf)) {
                   printf(" [서버] 클라이언트(%s) 연결 종료 (로그아웃 확인).\n", cli->username);
                   goto cleanup;
               }
               
               if (strcmp(input_buf, "Y") == 0 || strcmp(input_buf, "y") == 0) {
                   send_with_length(sock, " 로그아웃되었습니다. 초기 메뉴로 돌아갑니다.\n");
                   printf(" [서버] 클라이언트 %s(%s) 로그아웃 (소켓 %d)\n", cli->name, cli->username, sock);
                   logout_requested = 1;
                   break;
               } else if (strcmp(input_buf, "N") == 0 || strcmp(input_buf, "n") == 0) {
                   send_with_length(sock, " 로그아웃을 취소합니다.\n");
               } else {
                   send_with_length(sock, " 잘못된 입력입니다. Y 또는 N을 입력해주세요.\n");
               }
           } else {
               send_with_length(sock, " 잘못된 입력입니다. 다시 선택해주세요.\n");
           }
       } // end of 메인 메뉴 루프
       
       // 로그아웃된 경우 다시 초기 메뉴로 돌아가기
       if (logout_requested) {
           continue; // 전체 세션 루프의 처음으로 돌아가서 다시 로그인 메뉴 표시
       }
   } // end of 전체 세션 루프

cleanup:
   cleanup_client_room(cli);

   printf(" [서버] 클라이언트 연결 종료: %s (%s, 소켓 %d)\n", cli->name, cli->username, sock);
   close(sock);

   pthread_mutex_lock(&mutex);
   for (int i = 0; i < MAX_CLIENTS; ++i) {
       if (clients[i] == cli) {
           clients[i] = NULL;
           client_count--;
           break;
       }
   }
   pthread_mutex_unlock(&mutex);
   free(cli);
   return NULL;
}

int main(int argc, char* argv[]) {
    int serv_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;

    if (argc != 2) {
        printf("Usage: %s <PORT>\n", argv[0]);
        exit(1);
    }

    // MySQL 라이브러리 초기화 및 연결
    mysql_library_init(0, NULL, NULL);
    conn = mysql_init(NULL);
    if (!conn) {
        fprintf(stderr, "MySQL init error\n");
        exit(1);
    }

    if (!mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT, NULL, 0)) {
        fprintf(stderr, "MySQL connect error: %s\n", mysql_error(conn));
        exit(1);
    }
    printf("[MySQL] DB 연결 성공\n");

    // 서버 소켓 생성
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) error_handling("socket() error");

    // TIME_WAIT 상태를 피하기 위한 SO_REUSEADDR 옵션 설정
    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    // 소켓 바인딩
    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    
    // 연결 요청 대기
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");
    
    printf("[서버] 포트 %d에서 대기 중...\n", atoi(argv[1]));

    // 클라이언트 포인터 배열 초기화
    for(int i = 0; i < MAX_CLIENTS; ++i) {
        clients[i] = NULL;
    }

    while (1) {
        clnt_adr_sz = sizeof(clnt_adr);
        int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        if (clnt_sock == -1) {
            perror("accept error");
            continue;
        }

        pthread_mutex_lock(&mutex);
        // 비어있는 clients 배열 슬롯 찾기
        int idx = -1;
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i] == NULL) {
                idx = i;
                break;
            }
        }

        if (idx == -1) { // 최대 접속 수 초과
            send_with_length(clnt_sock, "서버에 접속자가 많아 연결할 수 없습니다.\n");
            close(clnt_sock);
            pthread_mutex_unlock(&mutex);
            printf("[서버] 최대 접속 수 도달, 새 연결 거부\n");
            continue;
        }

        // 새로운 Client 구조체 동적 할당
        Client* cli = malloc(sizeof(Client));
        if (!cli) {
            perror("malloc error for Client");
            close(clnt_sock);
            pthread_mutex_unlock(&mutex);
            continue;
        }

        cli->sock = clnt_sock;
        cli->is_admin = 0;
        cli->is_muted = 0;
        cli->room[0] = '\0';
        // 초기 username은 임시로 "Guest[소켓번호]"로 설정 (로그인 후 실제 ID로 업데이트)
        snprintf(cli->username, ID_LEN - 1, "Guest%d", clnt_sock);
        cli->username[ID_LEN - 1] = '\0';
        // 초기 name도 임시로 설정
        snprintf(cli->name, ID_LEN - 1, "게스트%d", clnt_sock);
        cli->name[ID_LEN - 1] = '\0';


        clients[idx] = cli; // 포인터를 배열에 저장
        client_count++;

        // chat_session 스레드 생성 (Client* 포인터를 인자로 전달)
        pthread_create(&cli->tid, NULL, chat_session, (void*)cli);
        pthread_detach(cli->tid); // 스레드 자동 소멸 설정

        pthread_mutex_unlock(&mutex);

        printf("[서버] 새로운 클라이언트 접속 시도: Guest%d (%s:%d), 현재 접속자: %d명\n",
               clnt_sock, inet_ntoa(clnt_adr.sin_addr), ntohs(clnt_adr.sin_port), client_count);
    }
    
    // 서버 종료 처리
    close(serv_sock);
    mysql_close(conn);
    mysql_library_end();
    return 0;
}
