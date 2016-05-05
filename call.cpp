/*
This is a modified copy of a pintool file provided in Pin Kit.
*/

#include "pin.H"
#include "portability.H"
#include <vector>
#include <iomanip>
#include <fstream>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <unistd.h> 
#include <time.h>
#include <unordered_set>
#include <set>


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
    "o", "call.out", "trace file");
KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
    "i", "0", "append pid to output");
KNOB<THREADID>   KnobWatchThread(KNOB_MODE_WRITEONCE,                "pintool",
    "watch_thread", "-1", "thread to watch, -1 for all");
KNOB<BOOL>   KnobFlush(KNOB_MODE_WRITEONCE,                "pintool",
    "flush", "0", "Flush output after every instruction");
KNOB<BOOL>   KnobSymbols(KNOB_MODE_WRITEONCE,       "pintool",
    "symbols", "1", "Include symbol information");
KNOB<BOOL>   KnobLines(KNOB_MODE_WRITEONCE,       "pintool",
    "lines", "0", "Include line number information");
KNOB<BOOL>   KnobTraceInstructions(KNOB_MODE_WRITEONCE,       "pintool",
    "instruction", "0", "Trace instructions");
KNOB<BOOL>   KnobTraceCalls(KNOB_MODE_WRITEONCE,       "pintool",
    "call", "1", "Trace calls");
KNOB<BOOL>   KnobTraceMemory(KNOB_MODE_WRITEONCE,       "pintool",
    "memory", "0", "Trace memory");
KNOB<BOOL>   KnobSilent(KNOB_MODE_WRITEONCE,       "pintool",
    "silent", "0", "Do everything but write file (for debugging).");
KNOB<BOOL> KnobEarlyOut(KNOB_MODE_WRITEONCE, "pintool", "early_out", "0" , "Exit after tracing the first region.");
/* ===================================================================== */
// Create a Trace_File for each thread to avoid racing
INT32 Num_Threads = 0;
static TLS_KEY Tls_Key;
PIN_LOCK Lock;
class ThreadData
{
  public:
    	FILE* Trace_File;
};
// function to access thread-specific data
ThreadData* get_tls(THREADID thread_id)
{
    ThreadData* tdata = 
          static_cast<ThreadData*>(PIN_GetThreadData(Tls_Key, thread_id));
    return tdata;
}

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

LOCALVAR INT32 enabled = 1;
string File_Name = "call";//output file name
LOCALFUN VOID Fini(int, VOID * v);

/* ===================================================================== */
//Helper Functions
string FormatAddress(ADDRINT address, RTN rtn)
{
    string s = "";// StringFromAddrint(address);
    
    if (KnobSymbols && RTN_Valid(rtn))
    {
        s += " " /*+ IMG_Name(SEC_Img(RTN_Sec(rtn))) + ":"*/;
        s += RTN_Name(rtn);
    }
	else if (KnobSymbols && !RTN_Valid(rtn))
	{
		s += " ";
		s += "invalid";
	}
    return s;
}

LOCALFUN BOOL Emit(THREADID threadid)
{
    if (!enabled || 
        KnobSilent || 
        (KnobWatchThread != static_cast<THREADID>(-1) && KnobWatchThread != threadid))
        return false;
    return true;
}

/* ===================================================================== */
/*                            Analysis Routines                          */
/* ===================================================================== */
VOID EmitDirectCall(THREADID threadid, string * str, INT32 tailCall)
{
    if (!Emit(threadid))
        return;
    ThreadData* tdata = get_tls(threadid);
    fprintf(tdata->Trace_File, "%s\n", (*str).c_str());    
    PIN_LockClient();
    CheckIfUnique(*str);//ignore thread id
    PIN_UnlockClient();
}

VOID EmitIndirectCall(THREADID threadid, string * str, ADDRINT target)
{
    if (!Emit(threadid))
        return;
    PIN_LockClient();
    string s = FormatAddress(target, RTN_FindByAddress(target));
    CheckIfUnique((*str) + s);
    PIN_UnlockClient();
	ThreadData* tdata = get_tls(threadid);
	fprintf(tdata->Trace_File, "%s%s\n", (*str).c_str(), s.c_str());
}

VOID EmitReturn(THREADID threadid, string * str)
{
    if (!Emit(threadid))
        return;
    ThreadData* tdata = get_tls(threadid);
    fprintf(tdata->Trace_File, "%s\n", (*str).c_str() );
	PIN_LockClient();
    CheckIfUnique(*str);
    PIN_UnlockClient();
}

/* ===================================================================== */      
//Helper function called by instrumentation routine to insert analysis routines
        
VOID CallTrace(TRACE trace, INS ins)
{
    if (!KnobTraceCalls)
        return;

    if (INS_IsCall(ins) && !INS_IsDirectBranchOrCall(ins))
    {
        // Indirect call
        string s = "C" + FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
        s += " ";
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitIndirectCall), IARG_THREAD_ID,
                       IARG_PTR, new string(s), IARG_BRANCH_TARGET_ADDR, IARG_END);
    }
    else if (INS_IsDirectBranchOrCall(ins))
    {
        // Is this a tail call?
        RTN sourceRtn = TRACE_Rtn(trace);
        RTN destRtn = RTN_FindByAddress(INS_DirectBranchOrCallTargetAddress(ins));

        if (INS_IsCall(ins)         // conventional call
            || sourceRtn != destRtn // tail call
        )
        {
            BOOL tailcall = !INS_IsCall(ins);
            
            string s = "";
            if (tailcall)
            {
                s += "T";
            }
            else
            {
                if( INS_IsProcedureCall(ins) )
                    s += "C";
                else
                {
                    s += "PcMaterialization";
                    tailcall=1;
                }
                
            }
            //s += INS_Mnemonic(ins) + " ";
            s += FormatAddress(INS_Address(ins), TRACE_Rtn(trace));
            //s += " ";
            ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
            s += FormatAddress(target, RTN_FindByAddress(target));
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitDirectCall),
                           IARG_THREAD_ID, IARG_PTR, new string(s), IARG_BOOL, tailcall, IARG_END);
        }
    }
    else if (INS_IsRet(ins))
    {
        RTN rtn =  TRACE_Rtn(trace);
#if defined(TARGET_LINUX) && defined(TARGET_IA32)
//        if( RTN_Name(rtn) ==  "_dl_debug_state") return;
        if( RTN_Valid(rtn) && RTN_Name(rtn) ==  "_dl_runtime_resolve") return;
#endif
        string tracestring = "R" + FormatAddress(INS_Address(ins), rtn);
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(EmitReturn),
                       IARG_THREAD_ID, IARG_PTR, new string(tracestring), IARG_END);
    } 
}
     
/* ===================================================================== */
/*                            Instrumentation Routine                    */
/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
	//get trace address
	UINT64 trace_addr = TRACE_Address(trace);
	//get image object by ID
	IMG img = IMG_FindByAddress(trace_addr);
	//check image validity
	if(!IMG_Valid(img)) return;
	//loop through instructions of each basic block
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
        	if(INS_IsCall(ins) || INS_IsDirectBranchOrCall(ins) || INS_IsRet(ins))
        	{
        	    //insert analysis routine(s)
            	CallTrace(trace, ins);
            }
        }
    }
}
/* ===================================================================== */
//Pin Thread-start notification function
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	//Create Trace_File for this thread
	PIN_GetLock(&Lock, threadid+1);
	Num_Threads++;
	PIN_ReleaseLock(&Lock);
	ThreadData* tdata = new ThreadData;
	PIN_SetThreadData(Tls_Key, tdata, threadid);
	ostringstream os;
	string file_name = File_Name;
	os << (threadid+1);
	file_name += os.str();//thread id
	file_name += ".out";
	tdata->Trace_File = fopen(file_name.c_str(),"w");
	
}
/* ===================================================================== */

VOID Fini(int, VOID * v)
{
	//Close Trace_File of each thread
	ThreadData* tdata;
	for(int t = 0; t < Num_Threads; t++)
	{
	 	tdata = get_tls(t);
	 	fclose(tdata->Trace_File);
	}
}
/* ===================================================================== */

int main(int argc, CHAR *argv[])
{
	PIN_InitLock(&Lock);
    PIN_InitSymbols();
    PIN_Init(argc,argv);
	PIN_AddThreadStartFunction(ThreadStart, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();
    return 0;
}

