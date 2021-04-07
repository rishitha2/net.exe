#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>


int getUse(int argc, wchar_t* argv[])
{
    DWORD res1, i, er = 0, tr = 0, resume = 0;
    PCONNECTION_INFO_1 p, b;
    LPTSTR lpszServer = NULL, lpszShare = NULL;

    if (argc < 2)
        wprintf(L"Syntax: %s [ServerName] ShareName | \\\\ComputerName\n", argv[0]);
    else
    {
        //
        // The server is not the default local computer.
        //
        if (argc > 2)
            lpszServer = argv[1];
        //
        // ShareName is always the last argument.
        //
        lpszShare = argv[argc - 1];
        //
        // Call the NetConnectionEnum function,
        //  specifying information level 1.
        //
        res1 = NetConnectionEnum(lpszServer, lpszShare, 1, (LPBYTE*)&p, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
        //
        // If no error occurred,
        //
        if (res1 == 0)
        {
            //
            // If there were any results,
            //
            if (er > 0)
            {
                b = p;
                //
                // Loop through the entries; print user name and network name.
                //
                for (i = 0; i < er; i++)
                {
                    printf("%S\t%S\n", b->coni1_username, b->coni1_netname);
                    b++;
                }
                // Free the allocated buffer.
                //
                NetApiBufferFree(p);
            }
            // Otherwise, print a message depending on whether 
            //  the qualifier parameter was a computer (\\ComputerName)
            //  or a share (ShareName).
            //
            else
            {
                if (lpszShare[0] == '\\')
                    printf("No connection to %S from %S\n",
                        (lpszServer == NULL) ? TEXT("LocalMachine") : lpszServer, lpszShare);
                else
                    printf("No one connected to %S\\%S\n",
                        (lpszServer == NULL) ? TEXT("\\\\LocalMachine") : lpszServer, lpszShare);
            }
        }
        //
        // Otherwise, print the error.
        //
        else
            printf("Error: %d\n", res1);
    }
    return 0;
}

int getUser(int argc, wchar_t* argv[])
{
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = NULL;

    if (argc > 2)
    {
        fwprintf(stderr, L"Usage: %s [\\\\ServerName]\n", argv[0]);
        exit(1);
    }
    // The server is not the default local computer.
    //
    if (argc == 2)
        pszServerName = (LPTSTR)argv[1];
    wprintf(L"\nUser account on %s: \n", pszServerName);
    //
    // Call the NetUserEnum function, specifying level 0; 
    //   enumerate global user account types only.
    //
    do // begin do
    {
        nStatus = NetUserEnum((LPCWSTR)pszServerName,
            dwLevel,
            FILTER_NORMAL_ACCOUNT, // global users
            (LPBYTE*)&pBuf,
            dwPrefMaxLen,
            &dwEntriesRead,
            &dwTotalEntries,
            &dwResumeHandle);
        //
        // If the call succeeds,
        //
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
        {
            if ((pTmpBuf = pBuf) != NULL)
            {
                //
                // Loop through the entries.
                //
                for (i = 0; (i < dwEntriesRead); i++)
                {
                    assert(pTmpBuf != NULL);

                    if (pTmpBuf == NULL)
                    {
                        fprintf(stderr, "An access violation has occurred\n");
                        break;
                    }
                    //
                    //  Print the name of the user account.
                    //
                    wprintf(L"\t-- %s\n", pTmpBuf->usri0_name);

                    pTmpBuf++;
                    dwTotalCount++;
                }
            }
        }
        //
        // Otherwise, print the system error.
        //
        else
            fprintf(stderr, "A system error has occurred: %d\n", nStatus);
        //
        // Free the allocated buffer.
        //
        if (pBuf != NULL)
        {
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    }
    // Continue to call NetUserEnum while 
    //  there are more entries. 
    // 
    while (nStatus == ERROR_MORE_DATA); // end do
    //
    // Check again for allocated memory.
    //
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    //
    // Print the final count of users enumerated.
    //
    fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);

    return 0;
}


int getGroups(int argc, wchar_t* argv[])
{
    PNET_DISPLAY_GROUP pBuff, p;
    DWORD res, dwRec, i = 0;
    //
    // You can pass a NULL or empty string
    //  to retrieve the local information.
    //
    TCHAR szServer[255] = TEXT("");

    if (argc > 1)
        //
        // Check to see if a server name was passed;
        //  if so, convert it to Unicode.
        //
        MultiByteToWideChar(CP_ACP, 0, 0, -1, szServer, 255);

    do // begin do
    {
        //
        // Call the NetQueryDisplayInformation function;
        //   specify information level 3 (group account information).
        //
        res = NetQueryDisplayInformation(szServer, 3, i, 1000, MAX_PREFERRED_LENGTH, &dwRec, (PVOID*)&pBuff);
        //
        // If the call succeeds,
        //
        if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
        {
            p = pBuff;
            for (; dwRec > 0; dwRec--)
            {
                //
                // Print the retrieved group information.
                //
                printf("Name:      %S\n"
                    "Comment:   %S\n"
                    "Group ID:  %u\n"
                    "Attributes: %u\n"
                    "--------------------------------\n",
                    p->grpi3_name,
                    p->grpi3_comment,
                    p->grpi3_group_id,
                    p->grpi3_attributes);
                //
                // If there is more data, set the index.
                //
                i = p->grpi3_next_index;
                p++;
            }
            //
            // Free the allocated memory.
            //
            NetApiBufferFree(pBuff);
        }
        else
            printf("Error: %u\n", res);
        //
        // Continue while there is more data.
        //
    } while (res == ERROR_MORE_DATA); // end do
    return 0;
}

int getShare(int argc, TCHAR* lpszArgv[])
{
    PSHARE_INFO_502 BufPtr, p;
    NET_API_STATUS res2;
    LPTSTR   lpszServer = NULL;
    DWORD er = 0, tr = 0, resume = 0, i;

    switch (argc)
    {
    case 2:
        lpszServer = lpszArgv[1];
        break;
    default:
        printf("Usage: NetShareEnum <servername>\n");
        return 0;
    }
    //
    // Print a report header.
    //
    printf("Share:              Local Path:                   Uses:   Descriptor:\n");
    printf("---------------------------------------------------------------------\n");
    //
    // Call the NetShareEnum function; specify level 502.
    //
    do // begin do
    {
        res2 = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
        //
        // If the call succeeds,
        //
        if (res2 == ERROR_SUCCESS || res2 == ERROR_MORE_DATA)
        {
            p = BufPtr;
            //
            // Loop through the entries;
            //  print retrieved data.
            //
            for (i = 1; i <= er; i++)
            {
                printf("%-20S%-30S%-8u ", p->shi502_netname, p->shi502_path, p->shi502_current_uses );
               
                //
                // Validate the value of the 
                //  shi502_security_descriptor member.
                //
                if (IsValidSecurityDescriptor(p->shi502_security_descriptor))
                    printf("Yes\n");
                else
                    printf("No\n");
                p++;
            }
            //
            // Free the allocated buffer.
            //
            NetApiBufferFree(BufPtr);
        }
        else
            printf("Error: %ld\n", res2);
    }
    // Continue to call NetShareEnum while 
    //  there are more entries. 
    // 
    while (res2 == ERROR_MORE_DATA); // end do
    return 0;
}






int wmain(int argc, wchar_t* argv[])
{
    LPGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;
    DWORD res, res1, res2, res3;

    if (argc != 2)
    {
        fwprintf(stderr, L"Usage: %s \\\\ServerName UserName\n", argv[0]);
        exit(1);
    }
    //
    // Call the NetLocalGroupEnum function, specifying level 0.
    //
    nStatus = NetLocalGroupEnum(argv[1],
        0,
        (LPBYTE*)&pBuf,
        dwPrefMaxLen,
        &dwEntriesRead,
        &dwTotalEntries,
        0);
    //
    // If the call succeeds,
    //
    if (nStatus == NERR_Success)
    {
        LPGROUP_USERS_INFO_0 pTmpBuf;
        DWORD i;
        DWORD dwTotalCount = 0;

        if ((pTmpBuf = pBuf) != NULL)
        {
            fprintf(stderr, "\nLocal group(s):\n");
            //
            // Loop through the entries; 
            //  print the name of the locals groups 
            //  to which the user belongs.
            //
            for (i = 0; i < dwEntriesRead; i++)
            {
                assert(pTmpBuf != NULL);

                if (pTmpBuf == NULL)
                {
                    fprintf(stderr, "An access violation has occurred\n");
                    break;
                }

                wprintf(L"\t-- %s\n", pTmpBuf->grui0_name);

                pTmpBuf++;
                dwTotalCount++;
            }
        }

    }
    else
        fprintf(stderr, "A system error has occurred: %d\n", nStatus);
    //
    // Free the allocated buffer.
    //
    if (pBuf != NULL)
        NetApiBufferFree(pBuf);

    printf("Thelist of serves for the workfgroup is not available ");
    nStatus = getUser(argc, argv);
    res = getGroups(argc, argv);
    res1 = getUse(argc, argv);
    res2 = getShare(argc, argv);
    

    return 0;


}



