using System;
using System.Collections.Generic;
using System.Text;

namespace Tireless.Net.Mail
{
    /* 127.0.0.2	SBL	Spamhaus SBL Data
     * 127.0.0.3	SBL	Spamhaus SBL CSS Data
     * 127.0.0.4	XBL	CBL Data
     * 127.0.0.9	SBL	Spamhaus DROP/EDROP Data (in addition to 127.0.0.2, since 01-Jun-2016)
     * 127.0.0.10	PBL	ISP Maintained
     * 127.0.0.11	PBL	Spamhaus Maintained */

    enum SpamhausResult
    {
        NL = 0, //Not listed
        SBL = 2, //Spamhaus Block List
        SBLCSS = 3,
        XBL = 4, //Exploits Block List
        DROP = 9, //DROP/EDROP
        PBL_ISP = 10, //Policy Block List (end-user IP address ranges)
        PBL = 11 //Policy Block List (end-user IP address ranges)
    }
}
