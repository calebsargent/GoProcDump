# GoProcDump
Golng version of SharpDump that can be used to extract LSASS or any other proces. Uses the WIN32 API via MiniDumpWriteDump and provides token elevation prior to creating dump of high intergrity processes.

# Usage
```
GoProcDump.exe -h
Usage of GoProcDump.exe:
  -l    Extract LSASS
  -p    PID to extract
  ```
  # Requires
  Finding the LSASS process by name requires the following project.
  ```
  To Install:
  go get github.com/mitchellh/go-ps
  ```
