#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <immintrin.h>
#include "fpe.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define DB_HOST "127.0.0.1"
#define DB_USER "root"
#define DB_PASS "PIPODB"
#define DB_NAME "PIPODB"
#define DB_TABLE "FF1_PIPO"
/*
char query[255];
void printError(MYSQL *conn);
void Set_Connection(MYSQL *conn);
void Create_DB(MYSQL *conn);
void Create_Table(MYSQL *conn);
void Delete_Table(MYSQL *conn);
void Delete_data(MYSQL *conn, char *ID);
void Insert_EncData(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc, const unsigned char *userKey);
void Insert_Data(MYSQL *conn);
void Show_data(MYSQL *conn);
*/
void Insert_EncData(unsigned int *in, unsigned int *out, unsigned int inlen, FPE_KEY *key, const int enc, const unsigned char *userKey);
void hex2chars(unsigned char hex[], unsigned char result[])
{
    int len = strlen(hex);
    unsigned char temp[3];
    temp[2] = 0x00;

    int j = 0;
    for (int i = 0; i < len; i += 2) {
        temp[0] = hex[i];
        temp[1] = hex[i + 1];
        result[j] = (char)strtol(temp, NULL, 16);
        ++j;
    }
}

void map_chars(unsigned char str[], unsigned int result[])
{
    int len = strlen(str);

    for (int i = 0; i < len; ++i)
        if (str[i] >= 'a')
            result[i] = str[i] - 'a' + 10;
        else
            result[i] = str[i] - '0';
}

void inverse_map_chars(unsigned result[], unsigned char str[], int len)
{
    for (int i = 0; i < len; ++i)
        if (result[i] < 10)
            str[i] = result[i] + '0';
        else
            str[i] = result[i] - 10 + 'a';

    str[len] = 0x00;
}

int main(int argc, char *argv[])
{


if (argc != 5) {
        printf("Usage: %s <key> <tweak> <radix> <plaintext>\n", argv[0]);
        return 0;
    }

    unsigned char k[100],
                  t[100],
                  result[300];
    int xlen = strlen(argv[4]),
        klen = strlen(argv[1]) / 2,
        tlen = strlen(argv[2]) / 2,
        radix = atoi(argv[3]);
    unsigned int x[300],
                 y[xlen];
    unsigned int tmp;

    hex2chars(argv[1], k);
    hex2chars(argv[2], t);
    map_chars(argv[4], x);

    for (int i = 0; i < xlen; ++i)
        assert(x[i] < radix);
        
    FPE_KEY ff1;

    printf("key:");
    for (int i = 0; i < klen; ++i)    printf(" %02x", k[i]);
    puts("");
    if (tlen)    printf("tweak:");
    for (int i = 0; i < tlen; ++i)    printf(" %02x", t[i]);
    if (tlen)    puts("");

    FPE_set_ff1_key(k, klen * 8, t, tlen, radix, &ff1);

    printf("after map: ");
    for (int i = 0; i < xlen; ++i)    printf(" %d", x[i]);
    printf("\n\n");

    printf("========== FF1 ==========\n");

    
    //MYSQL *conn = mysql_init(NULL);
    //Set_Connection(conn); //mysql 연결
    //Create_DB(conn); //DB생성
    //Create_Table(conn); //Table생성
    
    struct timeval start, end;
    double mtime, seconds, useconds;

    gettimeofday(&start, NULL);
    
//근데 한번만 돌릴건데 평문길이를 길게랑 짧게 해서 해야됨 
    // 여기서 DB 암호화를 할 것임.. 
    Insert_EncData(x, y, xlen, &ff1, FPE_ENCRYPT, k);

gettimeofday(&end, NULL);

    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
    printf("time %lf \n",mtime);

    //Insert_Data(conn);
 /*
    printf("ciphertext(numeral string):");
    for (int i = 0; i < xlen; ++i)    printf(" %d", y[i]);
    printf("\n");
*/
    inverse_map_chars(y, result, xlen);
    printf("ciphertext: %s\n\n", result);

    /*
    // result 입력
    sprintf(query, "INSERT INTO %s VALUES('%s','%s')", DB_TABLE, "id05", result); //id, PW      
    if ( mysql_query(conn, query) ){
                printError(conn);
        }
   */ 
    memset(x, 0, sizeof(x));
    Insert_EncData(y, x, xlen, &ff1, FPE_DECRYPT, k);

    printf("plaintext:");
    for (int i = 0; i < xlen; ++i)    printf(" %d", x[i]);
    printf("\n\n");


    FPE_unset_ff1_key(&ff1);
    //FPE_unset_ff3_key(&ff3);

	// mysql_free_result(res);
    return 0;
}

/*
void Insert_Data(MYSQL *conn)
{
        mysql_query(conn, "USE PIPODB");
        if (mysql_query(conn, "INSERT INTO TEST VALUES ('Mr. Kim', 'password1')") )
{
                printError(conn);
        }
}

void Show_data(MYSQL *conn)
{
        mysql_query(conn, "SELECT * FROM PIPODB.TEST");
        MYSQL_RES *result = mysql_store_result(conn);
        if ( result == NULL ) { printError(conn); }

        int num_fields = mysql_num_fields(result);
        MYSQL_ROW row;
        while ( row = mysql_fetch_row(result) )
        {
                for( int i = 0; i<num_fields; i++)
                       printf("%s ", row[i] ? row[i] : "NULL");
                printf("\n");
        }
        mysql_free_result(result);
}


void Set_Connection(MYSQL *conn)
{
        if( conn == NULL )
        {
                fprintf(stderr, "%s\n", mysql_error(conn));
                exit(1);
        }

        if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, NULL, 0, NULL, 0) == NULL )
        {
                fprintf(stderr, "%s\n", mysql_error(conn));
                exit(1);
        }
}

void Create_DB(MYSQL *conn)
{
        sprintf(query, "CREATE DATABASE if not exists %s", DB_NAME);
        if ( mysql_query(conn, query) )
        {
                printError(conn);
        }
        // printf("Create DATABASE %s successfully\n", DB_NAME);
}

void Create_Table(MYSQL *conn)
{
        mysql_query(conn, "USE PIPODB");
        sprintf(query, "CREATE TABLE if not exists %s(ID varchar(%d), PW varchar(%d))", DB_TABLE, 20, 500);
        if ( mysql_query(conn, query) )
        {
                printError(conn);
        }
        // printf("Create table [%s.%s] successfully\n", DB_NAME, DB_TABLE);
}

void Delete_Table(MYSQL *conn)
{
        sprintf(query, "DELETE TABLE %s.%s", DB_NAME, DB_TABLE);
        if ( mysql_query(conn, query))
        {
                printError(conn);
        }
        printf("Delete table [%s.%s] successfully\n", DB_NAME, DB_TABLE);

}

void Delete_data(MYSQL *conn, char* ID)
{
        sprintf(query, "DELETE FROM %s.%s WHERE ID= '%s'", DB_NAME, DB_TABLE, ID);
        if ( mysql_query(conn, query))
        {
                printError(conn);
        }
        printf("Delete %s successfully\n", ID);

}
void printError(MYSQL *conn)
{
        fprintf(stderr, "%s\n", mysql_error(conn));
        mysql_close(conn);
        exit(1);
}*/
