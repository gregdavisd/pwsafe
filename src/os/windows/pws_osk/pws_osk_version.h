/*
 * Copyright (c) 2003-2023 Rony Shapiro <ronys@pwsafe.org>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */

#ifndef _PWS_OSK_VERSION_H_
#define _PWS_OSK_VERSION_H_

 // version.h is automatically generated from version.in by a custom
 // pre-build step that uses git's 'describe' function and
 // replaces "GITREV" with current git commit info.

 // Format: Major, Minor, Revision
 //   Revision  = 0 for all Formally Released versions
 //   Revision != 0 for all Intermediate versions

#define PRODUCTVER         1
#define STROSKPRODUCTVER   "1\0"

#define FILEVER        1
#define STROSKFILEVER  "1\0"

#endif // _PWS_OSK_VERSION_H_
