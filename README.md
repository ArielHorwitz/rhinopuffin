```
A simple cli tool for encrypting and decrypting files with symmetric encryption.

Usage: rhinopuffin [OPTIONS] [FILE]

Arguments:
  [FILE]  Input file (omit to read from stdin)

Options:
  -d, --decrypt              Decrypt (encrypt by default)
  -o, --output <OUTPUT>      Output file
  -k, --key-file <KEY_FILE>  Use a file as encryption/decryption key
  -r, --raw-key <RAW_KEY>    Use encryption/decryption key string instead of prompting
  -D, --delete               Remove input file
  -h, --help                 Print help
  -V, --version              Print version
```
