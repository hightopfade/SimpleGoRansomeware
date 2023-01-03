# Golang Ransomware

- needed simple ransomware to test a few things and didn't trust the existing ransomware code bases on git.
- it has both encryption and decryption routines inside, just uncomment the portion you want/need
  - encrypted files will have a .enc file extension
- the key is static inside of the code base
- targetExt is used to target specific file extensions
- compile with `go build -ldflags "-s -w" main.go`
