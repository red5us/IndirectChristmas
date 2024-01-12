
### Christmas with Indirect Syscalls

Implementing an injection method mentioned by [@Hexacorn](https://x.com/Hexacorn/status/1350437846398722049?s=20).

> This version of Christmas uses an indirect Syscalls method to avoid EDR/XDR Hooks.

This PoC creates multiple processes, where each process performs a specific task as part of the injection operation. Each child process will spawn another process and pass the required information via the command line.  The program follows the steps below:

1. The first child process creates the target process where the payload will be injected. The handle is inherited among all the following child processes.
2. The second child process will allocate memory in the target process. 
3. The third child process will change the previously allocated memory permissions to RWX. 
4. Following that, for every 1024 bytes of the payload, a process will be created to write those bytes.
5. Lastly, another process will be responsible for payload execution.

The PoC uses the RC4 encryption algorithm to encrypt a Havoc Demon payload. The program, `ChristmasPayloadEnc.exe`, will be responsible for encrypting the payload, and padding it to be multiple of 1024 (as required by the injection logic).

### References & Credits

https://github.com/Maldev-Academy/Christmas

https://www.linkedin.com/in/danielabay/

https://www.linkedin.com/in/lielb1/