/*
   YARA Rule Set
   Author: CSIRT.SK
   Date: 2019-02-05
   Identifier: malware reborn stub (hawkeye)
   Reference: csirt.gov.sk
*/

/* Rule Set ----------------------------------------------------------------- */

rule reborn_stub_cleaned {
   meta:
      description = "malware reborn stub (hawkeye)"
      author = "CSIRT.SK"
      reference = "csirt.gov.sk"
      date = "2019-02-05"
      hash1 = "b8be751e097dee53bcae76fcdd7591fd214fac3090bbfe83d00e98a912b25825"
   strings:
      $x1 = "HawkEye Keylogger - Reborn v9{0}{1} Logs{0}{2} \\ {3}{0}{0}{4}" fullword wide /* score: '32.00'*/
      $x2 = "HawkEye Keylogger - Reborn v9 - {0} Logs - {1} \\ {2}" fullword wide /* score: '31.00'*/
      $s3 = "_ProcessElevation" fullword ascii /* score: '26.00'*/
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '25.00'*/
      $s5 = "System.Object.GetHashCode" fullword ascii /* score: '21.00'*/
      $s6 = "get_Process_0" fullword ascii /* score: '21.00'*/
      $s7 = "Passwords" fullword ascii /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s8 = "System.Runtime.Serialization.SerializationBinder.BindToType" fullword ascii /* score: '20.00'*/
      $s9 = "Reborn Stub.exe" fullword wide /* score: '20.00'*/
      $s10 = "_KeyStrokeLogger" fullword ascii /* score: '19.00'*/
      $s11 = "processThreadCollection_0" fullword ascii /* score: '18.00'*/
      $s12 = "_FTPPassword" fullword ascii /* score: '18.00'*/
      $s13 = "processWindowStyle_0" fullword ascii /* score: '17.00'*/
      $s14 = "processStartInfo_0" fullword ascii /* score: '17.00'*/
      $s15 = "passwordfile" fullword wide /* score: '17.00'*/
      $s16 = "_ProcessProtection" fullword ascii /* score: '17.00'*/
      $s17 = "_ExecutionDelay" fullword ascii /* score: '17.00'*/
      $s18 = "processThread_0" fullword ascii /* score: '16.00'*/
      $s19 = "processModule_0" fullword ascii /* score: '16.00'*/
      $s20 = "_LogInterval" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule RFQ_ORDER {
   meta:
      description = "malware reborn stub (hawkeye) obfuscated"
      author = "CSIRT.SK"
      reference = "csirt.gov.sk"
      date = "2019-02-05"
      hash1 = "ad706ea60efdea537efc0b8f739b6970052802a154e4cfc6871ef73391177b95"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "fraxiXKfWQ==.exe" fullword ascii /* score: '21.17'*/
      $s3 = "RFQ-ORDER.exe" fullword wide /* score: '20.00'*/
      $s4 = "bRAzLr9djnrFQNbccsQP78PYpg1Xe6J4yS9/67GUb0vRg0zV5V5IXjwLZDIVKzaDAKY1EYevGTho6OLb4b41Y5ygqcue0X7iVLF6qlMVJhTuXOESfwAFFjwe9GyiyzKU" ascii /* score: '15.00'*/
      $s5 = "nrJ31H8TFKgMjDIZNcK6GqqVQ6DfXqdLLwApjiLDHrG7wPFUG9XFye7JGYAJusVknEqGK0V9g/K7CuaBrJ+ZHQamMT+2q4+wudFR1IppjRZO+9QFCNB/hVXZl4MCgL4t" ascii /* score: '15.00'*/
      $s6 = "GHnLrF8fcpy1hvV7rX7jHaKZYDXjOK0U8xJ8AZIj8Z2sNcYtftPGd1OS54tj4P5wGg7xVyCHUiXZq9utiGG59XyMpNrdUBpRvTiK7E+xCi3srCUvf2i58M3eBQVVtUTW" ascii /* score: '15.00'*/
      $s7 = "FskRYeq7RbWaNsdxKomT/CnOYtUnuwnjsjP8wbuCoAxW/i36SI9gr02hELCTdwWN7SAEkgEteSpQcddg4K1qH5HMxhcgpLY/n8aeG8Tibbgzr2N5NVJNeovQIlc254qy" ascii /* score: '15.00'*/
      $s8 = "zSz25rDAYaUc7yEG61N0zwB0hkSfjGBJZR1TDnfBJQOZWwSzoX1fKfRWHWCgVh6btnGu//O7ozW/EY7N" fullword ascii /* score: '14.42'*/
      $s9 = "xijfEGbvtoXjkiAviWS7wx3UHDVncl97/IwRaem00Vd7yyudjLCKbEwjkGECdst+FHbLVSwJW2bfPM34" fullword ascii /* score: '14.00'*/
      $s10 = "TsEHUh8iPgTns8Sx0C0AeVINhl87B8IhE0+jPwrXtkxCseBBWcopmEk98kIQJ4OCdp+ZyvEOaTBsNrPj" fullword ascii /* score: '14.00'*/
      $s11 = "lGmNpiRTb6EkVoiCy2iM7aLedsfktWTQx1bi6pswWorOl22SckRO+JIsbJI4pHIbbJD7nPyMKUbkS71I" fullword ascii /* score: '14.00'*/
      $s12 = "lZYk7q2aqpVRyrSzA12J7LAdNT4O6zx2m2OqKAfS1hsxcgImS37RykrCMgSkexWAyk1aYi38IH3Vb90aAtIOzIcitrKTnJrk2BwbMfatEGsMKJFzW43+2h6eWmlZJmw8" ascii /* score: '14.00'*/
      $s13 = "5ohH6EYslsV5CFl014njE/XuEYPWBlRi7q6+LyUJBuXvoYEDFXPDVJQ35qjKNKDy1OE6pWLAJwfgMzm4" fullword ascii /* score: '14.00'*/
      $s14 = "esCPSUXo93RjFL+3XVtMkVYGHolCLifXj5YJcUb823XsAbWEMS99WSnHT4LSbr4wApStd3HKBzWcx0arTKcKB4XgONh1aNYKUNoaBsYiUnqk6WyhyliiRonjgMXoTndK" ascii /* score: '14.00'*/
      $s15 = "5bUTTURdBG8UEd3kfg7XCG2jtueY1Pd+0hlyyFdxCYKNRwZZrDCNb+XJuLSFKhC4nf7R+woYDRHgqrxC" fullword ascii /* score: '14.00'*/
      $s16 = "LvXjp/KJp+RPGQb2/A2yjk+KIc4lp6shwavKXriJd9QXOC5KSsEugRUutpkEYnS+Xkj12N8D+zFVJ0tNFst0X+A/w9B5nOu8XqOdGBNMHzWVUlnC/J/EYO3QwAny0A2N" ascii /* score: '13.00'*/
      $s17 = "WfCFfsoSHmQ6L6SQNMZDZWmTk2IgK7APNjCGdobd/tm2mSwK/CblP+rVqJUTyw7RRfLnQljyRSv+vsCMDA3hm6tr3yyw8BL/3aW4rrHWi6JGm5shE0NTooqQuMPxozVI" ascii /* score: '13.00'*/
      $s18 = "N2vBcMD7Wprrhc3pBWFJqgFdyxgvXKvC57T3h7QI8FhCP1o6ZcoKMbkz1fxqg9sCPKSnM8O6UPs6SD9IiTLZnl6dGQi4cxMBAA3xft/TuraMG27NGnHeCvJHYqadv92u" ascii /* score: '13.00'*/
      $s19 = "GMHkECVAspYKQjuGnvCBkfyEABjiA" fullword ascii /* score: '12.00'*/
      $s20 = "= wHeys0K6NH4g -o)QdY/MT\"" fullword ascii /* score: '11.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

