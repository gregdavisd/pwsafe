/*
* Copyright (c) 2003-2023 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/

/**
 * \file Windows-specific implementation of file.h
 */

#ifndef __WX__
#include <afx.h>
#endif

#include <Windows.h>
#include <LMCONS.H> // for UNLEN definition
#include <shellapi.h>
#include <shlwapi.h>

#include <io.h>
#include <sys/stat.h>
#include <fstream>

#include "../typedefs.h"
#include "../file.h"
#include "../dir.h"
#include "../env.h"
#include "../debug.h"

#include "../../core/core.h"

const TCHAR pws_os::PathSeparator = _T('\\');

bool pws_os::FileExists(const stringT &filename)
{
  struct _stat statbuf;
  int status;

  status = _tstat(filename.c_str(), &statbuf);
  return (status == 0 && (statbuf.st_mode & _S_IFREG)); // stat() succeeded and we're a regular file (not a directory)
}

bool pws_os::FileExists(const stringT &filename, bool &bReadOnly)
{
  bool retval;
  bReadOnly = false;

  retval = pws_os::FileExists(filename); // false if not found or if a directory
  if (retval) {
    bReadOnly = (_taccess(filename.c_str(), W_OK) != 0);
  }
  return retval;
}

void pws_os::AddDrive(stringT &path)
{
  // Adds a drive letter to the path if not there, unless
  // empty string  or it's a UNC path (\\host\sharename...)
  using namespace pws_os;
  if (path.empty())
    return;
  if (!(path[0] == '\\' && path[1] == '\\')) {
    stringT drive, dir, file, ext;
    splitpath(path, drive, dir, file, ext);

    if (drive.empty()) {
      const stringT exedir = getexecdir();
      stringT exeDrive, dummy;
      splitpath(exedir, exeDrive, dummy, dummy, dummy);
      path = makepath(exeDrive, dir, file, ext);
    }
  }
}

static bool FileOP(const stringT &src, const stringT &dst,
                   UINT wFunc)
{
  // wrapper for SHFileOperation() for moving or copying from src to dst
  // create any intervening directories as necessary & automatically
  TCHAR szSource[_MAX_PATH + 1];
  TCHAR szDestination[_MAX_PATH + 1];

  // SHFileOperation() acts very oddly if files are missing a drive
  // (eg, renames to pwsafeN.psa instead of pwsafe.ibak)
  
  stringT srcD(src), dstD(dst);
  pws_os::AddDrive(srcD);
  pws_os::AddDrive(dstD);

  if (srcD.length() >= _MAX_PATH || dstD.length() >= _MAX_PATH)
    return false;

  const TCHAR *lpsz_current = srcD.c_str();
  const TCHAR *lpsz_new = dstD.c_str();

  _tcscpy_s(szSource, _MAX_PATH, lpsz_current);
  _tcscpy_s(szDestination, _MAX_PATH, lpsz_new);

  // Must end with double NULL
  szSource[srcD.length() + 1] = TCHAR('\0');
  szDestination[dstD.length() + 1] = TCHAR('\0');

  SHFILEOPSTRUCT sfop;
  memset(&sfop, 0, sizeof(SHFILEOPSTRUCT));
  sfop.hwnd = GetActiveWindow();
  sfop.wFunc = wFunc;
  sfop.pFrom = szSource;
  sfop.pTo = szDestination;
  sfop.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_SILENT | FOF_NOERRORUI;

  return (SHFileOperation(&sfop) == 0);
}

bool pws_os::RenameFile(const stringT &oldname, const stringT &newname)
{
  _tremove(newname.c_str()); // otherwise rename may fail if newname exists
  return FileOP(oldname, newname, FO_MOVE);
}

extern bool pws_os::CopyAFile(const stringT &from, const stringT &to)
{
  return FileOP(from, to, FO_COPY);
}

bool pws_os::DeleteAFile(const stringT &filename)
{
  return DeleteFile(filename.c_str()) == TRUE;
}

void pws_os::FindFiles(const stringT &filter, std::vector<stringT> &res)
{
  res.clear();
  _tfinddata_t fileinfo;
  intptr_t handle = _tfindfirst(filter.c_str(), &fileinfo);
  if (handle == -1)
    return;

  do {
    res.push_back(LPCTSTR(fileinfo.name));
  } while (_tfindnext(handle, &fileinfo) == 0);

  _findclose(handle);
}



std::FILE *pws_os::FOpen(const stringT &filename, const TCHAR *mode)
{
  std::FILE *fd = NULL;
  if (!filename.empty()) {
	  _tfopen_s(&fd, filename.c_str(), mode);
  } else { // set to stdin/stdout, depending on mode[0] (r/w/a)
	  fd = mode[0] == L'r' ? stdin : stdout;
  }
  return fd;
}

int pws_os::FClose(std::FILE *fd, const bool &bIsWrite)
{
  if (fd != NULL) {
    if (bIsWrite) {
      // Flush the data buffers
      // fflush returns 0 if the buffer was successfully flushed.
      // A return value of EOF indicates an error.
      int rc = fflush(fd);

      // Don't bother trying FlushFileBuffers if fflush failed
      if (rc == 0) {
        // Windows FlushFileBuffers == Linux fsync
        int ifileno = _fileno(fd);

        if (ifileno != INVALID_FILE_DESCRIPTOR) {
          intptr_t iosfhandle = _get_osfhandle(ifileno);

          if ((HANDLE)iosfhandle != INVALID_HANDLE_VALUE) {
            BOOL brc = FlushFileBuffers((HANDLE)iosfhandle);

            if (brc == FALSE) {
              pws_os::IssueError(_T("FlushFileBuffers on close of file on removable device"), false);
            }
          } // iosfhandle
        } // ifileno
      }  // fflush rc
    }

    // Now close file
    // fclose returns 0 if the stream is successfully closed or EOF to indicate an error.
    return fclose(fd);
  } else {
    return 0;
  }
}

ulong64 pws_os::fileLength(std::FILE *fp) {
  if (fp != nullptr) {
    __int64 pos = _ftelli64(fp);
    _fseeki64(fp, 0, SEEK_END);
    __int64 len = _ftelli64(fp);
    _fseeki64(fp, pos, SEEK_SET);
    return ulong64(len);
  } else
    return 0;
}

bool pws_os::GetFileTimes(const stringT &filename,
      time_t &atime, time_t &ctime, time_t &mtime)
{
  struct _stati64 info;
  int rc = _wstati64(filename.c_str(), &info);
  if (rc == 0) {
    atime = info.st_atime;
    ctime = info.st_ctime;
    mtime = info.st_mtime;
    return true;
  } else {
    return false;
  }
}

void TimetToFileTime(time_t t, FILETIME *pft)
{
  LONGLONG ll = Int32x32To64(t, 10000000) + 116444736000000000;
  pft->dwLowDateTime = (DWORD)ll;
  pft->dwHighDateTime = ll >> 32;
}

bool pws_os::SetFileTimes(const stringT &filename,
  time_t ctime, time_t mtime, time_t atime)
{
  FILETIME fctime, fmtime, fatime;

  if (ctime == 0 && mtime == 0 && atime == 0)
    return true;  // Nothing to do!

  // Convert to file time format
  TimetToFileTime(ctime, &fctime);
  TimetToFileTime(mtime, &fmtime);
  TimetToFileTime(atime, &fatime);

  // Now set file times
  HANDLE hFile;
  hFile = CreateFile(filename.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
    OPEN_EXISTING, 0, NULL);

  if (hFile != INVALID_HANDLE_VALUE) {
    SetFileTime(hFile, ctime != 0 ? &fctime : nullptr, atime == 0 ? &fatime : nullptr, mtime != 0 ? &fmtime : nullptr);
    CloseHandle(hFile);
    return true;
  } else {
    return false;
  }
}
