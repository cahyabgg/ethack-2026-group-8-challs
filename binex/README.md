# Really Secure Notes
by Group 8 Ethical Hacking 2026 CSCE604258

## Challenge Description
So I got a request to create a really secure notes tracking app, to make it secure I use the best compilation options. Logically nothing bad will happen right?

### Security Profile
* **Full RELRO**: GOT is read-only
* **Stack Canary**: Stack smashing is checked
* **NX**: Shellcode is non-executable
* **PIE**: Base addresses are randomized
* **O2**: Prune all unused instructions to keep binary size small
* **FORTIFY**: protect againts unsafe functions in runtime (e.g., printf, strcpy, read, memcpy)
* **SHSTK**: protect against "Backward-Edge" control-flow hijacking (like ROP)
* **IBT**: protect against "Forward-Edge" control-flow hijacking (like JOP)
* **fstack-clash-protection**: make cpu check stack every page interval
* **fno-delete-null-pointer-checks & fno-strict-overflow**: protect against null and overflow attack
* **Glibc 2.43**: No legacy malloc hooks available

---

## Validation Steps

### 1. Build and Sync Environment
The `start.sh` script automates the Docker build and extracts the exact `libc` and `ld` versions from the container to ensure local exploit stability.

```bash
chmod +x start.sh
./start.sh
```

### 2. Prepare the Solver
Navigate to the solve directory where the container binaries have been synchronized.

```bash
cd solve
```

### 3. Patch the Binary
Use `pwninit` (or `patchelf`) to link the challenge binary to the extracted loader and library. This ensures that your local offsets for `system` and gadgets match the remote environment perfectly.

```bash
pwninit
```

### 4. Execute the Exploit
Run the Python solver to perform the leak, calculate offsets, and trigger shell, use LOCAL for local and no args for remote solve.

```bash
python3 solution.py
```

