# QDime
QDime is a QoS-aware dynamic binary instrumentation tool that respects user-defined qaulity-of-service constraints during extraction of runtime information. QDime is a program analysis tool that reduces runtime overhead during instrumentation.

# Installation
Download Pin instrumentation framework (https://software.intel.com/en-us/articles/pintool-downloads)

# How to use
- Get familiar with Pin instrumentation framework (https://software.intel.com/en-us/articles/pintool/)
- Your working folder should include your pintool.cpp file and qdime.h
- Copy Makefile and Makefile.rules from any pintool folder to your working folder
- `#include qdime.h` in your pintool.cpp
- In `main()`, call `qdime_init()`
- In `Fini()`, call `qdime_fini()`
- In `ThreadStart()`, call `dime_thread_start(threadid)`
- In your instrumentation routine, call `qdime_switch_version()`
- In your analysis routines, call `qdime_start_time()` and `qdime_end_time()`
- To enable redundancy suppression, call `qdime_compare_to_log()` and `qdime_modify_log()` in your instrumentation routine
- Check call_qdime.cpp for an example.

# Commands
### To compile  
`make obj-intel64/pintool.so`	  
or `make obj-ia32/pintool.so`  
### To run pintool with qdime  
  **`pin -t obj-intel64/pintool.so -r <R> -th0 <T> -b <d> -ub <U> -p <P> -- app`**   
  such that:  
    `-r <R>`       : redundancy suppression run number R (0 to disable)  
    `-th0 <T>`      : threshold T  
    `-b <D>`        : default budgetD in [0,100] for when the threshold cannot be met. The default value is d=0, meaning no instrumentation  
    `-ub <U>`       : upper-bound U for the threshold. If supplied, U should be greater than T. Otherwise, the budget function without upper-bound will be used. The default value is U=0.  
    `-p <P>`        : instrumentation period P in seconds. The default value is P = 1 second. Ideally, this should be the rate at which the QoS metrics are extracted.  
    
