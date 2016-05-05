/*
This is a copy of a pintool provided in Pin Kit.
This pintool file is modified to utilize QDime.
*/

#include "pin.H"
#include "portability.H"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <stdio.h>
#include <unistd.h> 
#include <time.h>
#include <unordered_set>
#include <set>
#include "qdime.h"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
    "o", "debugtrace_call.out", "trace file");
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
/* Global Variables */
/* ===================================================================== */
LOCALVAR INT32 enabled = 1;
string File_Name = "call_qdime";//output file name
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
    //start QDime timer
	qdime_start_time();
    if (!Emit(threadid))
        return;
    ThreadData* tdata = get_tls(threadid);
    fprintf(tdata->Trace_File, "%s %d\n", (*str).c_str(), threadid );    
    PIN_LockClient();
    CheckIfUnique(*str);//ignore thread id
    PIN_UnlockClient();
    //stop QDime timer
    qdime_end_time();
}


VOID EmitIndirectCall(THREADID threadid, string * str, ADDRINT target)
{
    //start QDime timer
	qdime_start_time();
    if (!Emit(threadid))
        return;
    PIN_LockClient();
    string s = FormatAddress(target, RTN_FindByAddress(target));
    PIN_UnlockClient();
	ThreadData* tdata = get_tls(threadid);
	fprintf(tdata->Trace_File, "%s%s %d\n", (*str).c_str(), s.c_str(), threadid );
	PIN_LockClient();
    CheckIfUnique((*str) + s);
    PIN_UnlockClient();
    //stop QDime timer
    qdime_end_time();
}

VOID EmitReturn(THREADID threadid, string * str)
{
    //start QDime timer
	qdime_start_time();
    if (!Emit(threadid))
        return;
    ThreadData* tdata = get_tls(threadid);
    fprintf(tdata->Trace_File, "%s %d\n", (*str).c_str(), threadid );
	PIN_LockClient();
    CheckIfUnique(*str);
    PIN_UnlockClient();
    //stop QDime timer
    qdime_end_time();
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
	//get trace version
	ADDRINT version = TRACE_Version(trace);
	//get image low address
	UINT64 img_low_addr = IMG_LowAddress(img);
	//trace relative address
	UINT64 trace_rel_addr = trace_addr - img_low_addr;
	//get trace size
	USIZE trace_size = TRACE_Size(trace);
	//get current thread ID
	THREADID thread_id = PIN_ThreadId();
	//flag; if 0, instrumentation of current trace is disabled
	bool Allow_Instrum = 1;
	//Check log if redundancy suppression feature is ON
	if(Redun_Suppress)
	{
		Allow_Instrum = qdime_compare_to_log(thread_id, trace_rel_addr, trace_size);
	}	
	if(Allow_Instrum)
	{
	    //loop through instructions of each basic block
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
		    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		    {
		    	if(INS_IsCall(ins) || INS_IsDirectBranchOrCall(ins) || INS_IsRet(ins))
		    	{
		    	    //QDime: perform version switching if needed to respect QoS threshold
		        	qdime_switch_version(version, ins);
					switch(version) {
					  case VERSION_BASE:
					  	//Do Nothing (no analysis routine insertion)
						break;
					  case VERSION_INSTRUMENT:
					    //insert analysis routine(s)
						CallTrace(trace, ins);
						break;
					  default:
						assert(0);
						break;
					}
		        }
		    }
		}
		//update log if redundancy suppression feature is ON
		qdime_modify_log(version, thread_id, trace_rel_addr, trace_size);
    }
}

/* ===================================================================== */
//Pin Thread-start notification function
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    //call QDime thread-start notification function
	qdime_thread_start(threadid);
	//Create Trace_File for this thread
	ThreadData* tdata = get_tls(threadid);
	ostringstream os;
	string file_name = File_Name;
	os << (threadid+1);
	file_name += os.str();//thread id
	file_name += ".out";
	tdata->Trace_File = fopen(file_name.c_str(),"w");
}
/* ===================================================================== */
//Pin Fini notification function
VOID Fini(INT32 code, VOID * v)
{
    //Call QDime Fini function
	qdime_fini();
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
    //initialize Pin
    PIN_Init(argc,argv);
    //initialize QDime
    //arg: file name (this file will contain information aput QDime execution)
	qdime_init((char*)"qdime_info.out");
	//Pin Thread-start notification function
    PIN_AddThreadStartFunction(ThreadStart, 0);
    //Instrumentation routine at trace granularity
    TRACE_AddInstrumentFunction(Trace, 0);
    //Pin Fini notification function
    PIN_AddFiniFunction(Fini, 0);
    //start (Never returns)
    PIN_StartProgram();
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

