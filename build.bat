@echo off
echo Building GoPortScan...
go build -o goportscan.exe -ldflags="-s -w" .
echo Done: goportscan.exe
