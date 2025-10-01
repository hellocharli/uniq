# uniq

A high-performance Go tool for generating vanity cryptographic keys and hashes through brute-force computation.

## Features

- **NTLM Hash Generation**: Generate passwords with NTLM hashes matching a specified hex prefix
- **Ed25519 SSH Key Generation**: Generate SSH key pairs with base64 fingerprints matching a specified prefix
- **Multi-core Processing**: Utilizes all available CPU cores for maximum performance
- **Progress Tracking**: Real-time statistics showing attempts per second and estimated completion time
- **Multiple Results**: Generate multiple matching results in a single run
- **Optimized Performance**: Memory pooling and batch processing for high throughput

## Installation

```bash
git clone git@github.com:hellocharli/uniq.git
cd uniq
go build -o uniq .
```

## Usage

### NTLM Hash Generation

Generate passwords whose NTLM hashes start with a specific hex prefix:

```bash
./uniq ntlm [-n|--number NUM_RESULTS] prefix
```

### Ed25519 SSH Key Generation

Generate SSH key pairs whose fingerprints start with a specific base64 prefix:

```bash
./uniq ed25519 [-n|--number NUM_RESULTS] prefix
```

### Global Options

- `-n, --number`: Number of results to generate (default: 1)

## Examples

```bash
# Find a password with NTLM hash starting with "DEAD"
./uniq ntlm DEAD

# Find 5 passwords with NTLM hashes starting with "BABE"
./uniq ntlm -n 5 BABE

# Find an SSH key with a fingerprint starting with "+++"
./uniq ed25519 +++

# Find 3 SSH keys with fingerprints starting with "FERN"
./uniq ed25519 -n 3 FERN
```

## Output

The tool provides real-time statistics during generation:

- Current generation rate (hashes/keys per second)
- Total attempts made
- Estimated time to completion based on probability
- Progress indicators

```bash
./uniq ntlm 0123456
Searching for 1 NTLM hash with prefix: 0123456
Hashes: 310799942 │ H/s: 9923463
P99: 1236190959   │ ETA (75%): 37s
│█████████████████████████████████████████         │ 31s

Password  : p4ipntA4LPqDZl8C
NTLM Hash : 01234565DD77D7CDCE2719793C5D0233
```
```bash
./uniq ed25519 +/+/
Searching for 1 Ed25519 key with prefix: +/+/
Keys: 23865123 │ K/s: 859692
P99: 77261935  │ ETA (75%): 27s
│██████████████████████████████████████████████████│ 28s

Fingerprint : +/+/VGre74xbnQdgHZ0dSQDdmRQ6rtk1JubyOYVUJlU=
Public Key  : ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA9tJq352g0aQS5EFRoXieuLumibHS9xj28Uih6vLSAY
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACAPbSat+doNGkEuRBUaF4nri7pomx0vcY9vFIoery0gGAAA
AJg8dIalPHSGpQAAAAtzc2gtZWQyNTUxOQAAACAPbSat+doNGkEuRBUaF4nri7po
mx0vcY9vFIoery0gGAAAAECT+4//VmVqpV+z6oZWfdiFrQ6TO+arI4ZA7HysYoV0
iQ9tJq352g0aQS5EFRoXieuLumibHS9xj28Uih6vLSAYAAAAEDEgbGl0dGxlIGNv
bW1lbnQBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```
These examples were performed on a MacBook Pro with M4 Max.

## Performance

The tool is optimized for high performance with:

- Multi-core parallel processing
- Memory pooling to reduce allocations
- Batch processing to minimize context switching
- Efficient (standard library) cryptographic implementations

Generation rates vary greatly by hardware, but with how parallelized the workload is, more cores > faster cores.

This is *not* GPU accelerated and probably never will be. Meaningful performance gain from GPU acceleration would require rewriting MD4 or ed25519 generation in CUDA, which is significantly beyond my abilities.