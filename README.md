# MemScan

Given a particular dump the module can do the following things:
- Identification of the processes.
- Retrieving information from a process (process name, memory zone, virtual address, access rights).
- Recovery of the memory pages of a process.
- Search by patterns and extraction of intersting strings (emails, URLs, IP ..) in the  process memory (allocated and unalocated).
- Retrieving patterns from an external file.
- Display of the surroundings memory of a particular string (options
-A -B).
- Management of ASCII and Unicode encodings.

# Usage

`cp memscan.py PathTo/volatility-master/volatility/plugins`  
`python vol.py --plugins=PathTo/volatility-master/volatility/plugins -f YourDump --profile=DumpOperatingSystem  memscan [mescan option]`
