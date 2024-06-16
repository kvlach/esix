# esix

An 8086 disassembler. Outputs NASM-compatible assembly.

## Running

```sh
gcc -o esix sim86.c
./esix 'binary'
```

## Testing

The `./run <file.nasm>` script can be used for testing, it will:
1. Assemble `file.nasm`
2. Disassemble it using `esix`
3. Compare the two binaries

The source files provided by [Casey Muratori](https://github.com/cmuratori/computer_enhance/tree/main/perfaware/part1) may also be used:

```sh
git clone https://github.com/cmuratori/computer_enhance.git
./tests cmuratori/perfaware/part1
```
