/* QDime Header file*/
/* ===================================================================== */
/*
  @AUTHORS: 
*/
/* ===================================================================== */

#include <iostream>
#include <fstream>
#include <sstream>
#include <assert.h>
#include <unordered_map>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
// Shared memory includes
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <sys/time.h>


#define sec_to_nsec 1000000000//from second to nanosecond
#define usec_to_nsec 1000//from microsecond to nanosecond
#define Freq 3401 //grep 'cpu MHz' /proc/cpuinfo
#define rdtsc(low,high) \
     __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))

static struct itimerval Interval;//used by setitimer()
static ofstream Trace_File;//output file
static ofstream Trace_File2;//QDime execution info file
static INT64  Budget_Dec;//budget variable to decrement, in nanoseconds
static const INT32 MAX_SIZE = 86400;//enough to write a string of 11 char's every second for a full day
UINT32 Low_S, Low_E;//used by rdtsc()
UINT32 High_S, High_E;//used by rdtsc()
static REG Version_Reg;//used by INS_InsertVersionCase()
INT32 period_t_sec;//in seconds
INT32 period_t_usec;//in microseconds    
float percentage;//from 0% to 100% 
bool Init_zero = true; //get rid of initial zeros
INT32 split_period = 0; //to manage large instrumentation period: they are to be split into chunks of 1s
INT32 or_period; //to manage large instrumentation period
INT64 split_budget; //to manage large instrumentation period
// Shared memory variables
int shm_id;
key_t shm_key = 9491;
// performance metrics
typedef struct Metrics
{
	double var0;

} Metrics;

Metrics* pmetric;
Metrics threshold;
//for trace version switching
enum 
{
    VERSION_BASE,
    VERSION_INSTRUMENT
};

/* threshold knobs */
KNOB<double> KnobThresholdVar0(KNOB_MODE_WRITEONCE, "pintool", "th0", "100", "Threshold for var0");
KNOB<float> KnobBudget(KNOB_MODE_WRITEONCE, "pintool", "b", "0", "Default Budget Value");
/* Budget knobs */
KNOB<int> KnobPeriod(KNOB_MODE_WRITEONCE, "pintool", "p", "1", "Instrumentation Period");

//------------------
//Redundancy Suppression: the log is a hashtable (unordered_map)
// 0: Redundancy Suppression disabled (default)
KNOB<int> KnobRunNum(KNOB_MODE_WRITEONCE, "pintool", "r", "0", "Run Number (for redundancy suppression)");
BOOL Redun_Suppress = false; //redundancy suppression feature flag; when True, feature is ON
int Run_Num = 0;//QDime run number
/* ----------------------------------------------------------------- */
//For thread handling
static TLS_KEY Tls_Key;
PIN_LOCK Lock;
INT32 Num_Threads = 0;
class ThreadData
{
  public:
    ThreadData() : Previous_Trace(0), Previous_Size(0), Total_Test(0), Errors("") {}
    std::unordered_map<UINT64,USIZE> Log;//trace relative address, trace size: only for the instrumented traces
    UINT64 Previous_Trace;//relative address of previous trace whose version = 1
    USIZE Previous_Size;//size of previous trace whose version = 1
    int Total_Test;//total number of traces compared to Log
    string Errors;//error messages
	FILE* Trace_File;//use it if you need a Trace_File for each thread to avoid racing
};

// function to access thread-specific data
ThreadData* get_tls(THREADID thread_id)
{
    ThreadData* tdata = 
          static_cast<ThreadData*>(PIN_GetThreadData(Tls_Key, thread_id));
    return tdata;
}
/* =================================================================================== */
/*                            Budget Handling Functions                                */
/* =================================================================================== */
//Budget calculation function 
double getBudget(double qos)
{	
	
	if(qos>0.0) Init_zero = false;
	else if(Init_zero) return (1.0*(period_t_sec*sec_to_nsec + period_t_usec * usec_to_nsec));

	if(qos < threshold.var0) return (((float)percentage/100) * (period_t_sec * sec_to_nsec + period_t_usec * usec_to_nsec)); 
	return (((qos - threshold.var0)/qos) * (period_t_sec * sec_to_nsec + period_t_usec * usec_to_nsec));

}

/* ----------------------------------------------------------------- */
//Budget checking function
//returns 1 if we should disable instrumentation
static inline int qdime_break_threshold()
{
    return Budget_Dec <= 0;
}

/* =================================================================================== */
/*                            Trace Version Switching                                  */
/* =================================================================================== */
/*	According to Pin Documentation (https://software.intel.com/sites/landingpage/pintool/docs/76991/Pin/html/group__TRACE__VERSION__API.html):
	* INS_InsertVersionCase(): Insert a dynamic test to switch between versions before ins. If the value in reg matches case_value, then continue execution at ins with version version. Switching to a new version will cause execution to continue at a new trace starting with ins. This API can be called multiple times for the same instruction, creating a switch/case construct to select the version.
	* By default, all traces have a version value of 0. A trace with version value N only transfers control to successor traces with version value N. There are some situations where Pin will reset the version value to 0, even if executing a non 0 trace. This may occur after a system call, exception or other unusual control flow. 
*/
static inline void qdime_switch_version(ADDRINT version, INS ins)
{
    //check budget availability
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(qdime_break_threshold),
		                   IARG_RETURN_REGS, Version_Reg,IARG_END);
	//check if you need to switch to VERSION_INSTRUMENT
	if(version == VERSION_BASE) {  
		INS_InsertVersionCase(ins, Version_Reg, 0, VERSION_INSTRUMENT, IARG_END);      
	}
	//check if you need to switch to VERSION_BASE
	else if(version == VERSION_INSTRUMENT){  
		INS_InsertVersionCase(ins, Version_Reg, 1, VERSION_BASE, IARG_END);      
	}
}
/* =================================================================================== */
/*                            Timer Handling Functions                                 */
/* =================================================================================== */
/* ------------------------- Timer Start ---------------------------------------- */
static inline void qdime_start_time()
{
	rdtsc(Low_S,High_S);
}

/* --------------------------- Timer Stop -------------------------------------- */
static inline void qdime_end_time()
{
	rdtsc(Low_E,High_E);
	Budget_Dec -= (Low_E - Low_S)*1000/Freq;
	//Note: we ignore High_E and High_S since Analysis routine can never exceed 3.5 sec
	if((Budget_Dec <=0)&&(split_period>0)){
		Budget_Dec += split_budget;
		split_period--;
	}
}

/* --------------------------- Timer Signal Interceptor ------------------------- */
static BOOL reset_budget(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hashndlr, 
 			const EXCEPTION_INFO *exception, VOID *v)
{	
	if(sig==SIGVTALRM){		
		Budget_Dec = getBudget(pmetric->var0);		
		split_period = or_period-1;
		if(split_period>0) split_budget = Budget_Dec;
	}
	return hashndlr;	
}

/* ===================================================================== */
/*                            Redundancy Suppression Functions                   */
/* ===================================================================== */
//Redundancy suppression: read log of previously instrumented traces at initialization
int read_log(string file, THREADID thread_id)
{
	string line;
	ifstream myfile(file);
	int ret = 0;
	UINT64 tr;
	USIZE sz;
	ThreadData* tdata = get_tls(thread_id);
	if (myfile.is_open() && myfile.good())
	{
		while(getline (myfile,line,'\n'))
		{
			istringstream iss;
			iss.str(line);
			if(Run_Num > 1)//log
			{
				iss >> tr >> sz;
				tdata->Log[tr] = sz;
			}
		}
		ret = 1;
	 }
	 myfile.close();	
	 return ret;
}

/* ----------------------------------------------------------------- */
//Redundancy suppression: search log of instrumented traces
//returns 0 if trace_rel_addr is found
static inline bool qdime_compare_to_log(THREADID thread_id, UINT64 trace_rel_addr, USIZE trace_size)
{
	bool ret_val = 0;	
	if(Redun_Suppress)
	{	
		std::unordered_map<UINT64,USIZE>::iterator Iterator;
		ThreadData* tdata = get_tls(thread_id);
		if(tdata->Log.empty())
		{
			ret_val = 1;
		}
		else
		{
			tdata->Total_Test++;
			Iterator = tdata->Log.find(trace_rel_addr);
			//avg. case: constant, worst case: linear
			//check keys only (range checking is not possible)
			if(Iterator == tdata->Log.end())//not found
			{
				ret_val = 1;
			}
			else
			{
				//found as key
				ret_val = 0;
			}
		}
	}
	return ret_val;
}
/* ----------------------------------------------------------------- */
//Redundancy suppression: add trace relative address to the log of instrumented traces
static inline void qdime_modify_log(ADDRINT version, THREADID thread_id, UINT64 trace_rel_addr, USIZE trace_size)
{
	if(Redun_Suppress)
	{
		std::unordered_map<UINT64,USIZE>::iterator Iterator;
		ThreadData* tdata = get_tls(thread_id);
		USIZE new_size;
		if(version == VERSION_BASE && trace_rel_addr == tdata->Previous_Trace)
		{
			//handle the case in which: the trace initialy has version 1, 
			//then Pin checks budget, accordingly the trace switches to version 0
			//therefore, remove this trace from the log
			if(tdata->Log.erase(trace_rel_addr) != 1)
			{
				ostringstream ss;
				ss <<  "Error " << trace_rel_addr;
				tdata->Errors += ss.str();
				tdata->Errors += " not erased\n";
			}
			tdata->Previous_Trace = 0;
			tdata->Previous_Size = 0;
		}
		else if(version == VERSION_BASE && 
			tdata->Previous_Trace < trace_rel_addr && trace_rel_addr < (tdata->Previous_Trace + tdata->Previous_Size))
		{
			//Adjusting trace size.
			//handle the case in which: trace A is instrumented and saved in the log <A,size(A)
			//In the middle of the trace, the version is switched to version 0. So, modify size(A)
			Iterator = tdata->Log.find(tdata->Previous_Trace);
			//avg. case: constant, worst case: linear
			if(Iterator != tdata->Log.end())
			{
				new_size = trace_rel_addr - tdata->Previous_Trace;
				Iterator-> second = new_size;//modify
				tdata->Previous_Size = new_size;
			}
			else
			{
				ostringstream ss;
				ss << tdata->Previous_Trace << tdata->Previous_Size <<  trace_rel_addr;
				tdata->Errors += ss.str();
				tdata->Errors += " size not modified\n";
			}
		}
		else if(version == VERSION_INSTRUMENT)//record instrumented trace
		{
			tdata->Log[trace_rel_addr] = trace_size;
			//avg. case: constant, worst case: linear
			tdata->Previous_Trace = trace_rel_addr;
			tdata->PreviousTrace_File2_Size = trace_size;
		}
	}
}
/* ======================================================================================== */
//QDime fini notification function
static inline void qdime_fini()
{
		Trace_File2 << "Threshold = " << threshold.var0 << endl;
		Trace_File2 << "Shared memory variable (last value) = " << pmetric->var0 << endl;
		Trace_File2 << "Default Budget = " << percentage << endl;
		Trace_File2 << "Budget (last value) = " << Budget_Dec << endl;
		Trace_File2 << "Period  = " << period_t_sec << endl;
		Trace_File2.close();
    
    if(Redun_Suppress)
    {
		//Write to log file if redundancy suppression feature is ON
		for(int t = 0; t < Num_Threads; t++)
		{
			ostringstream ss;
		 	ss << (t + 1);
		 	string file = "log";
		 	file += ss.str();//thread id
		 	file += ".out";
		 	ofstream logfile;//log file
			logfile.open(file, std::ofstream::out);
			ThreadData* tdata = get_tls(t);
			for ( auto it = tdata->Log.begin(); it != tdata->Log.end(); ++it )
			{
				logfile << it->first << " " << it->second << endl;
			}
			logfile.close();
		}
	}
}

/* ======================================================================================== */
//QDime thread-start notification function
static inline void qdime_thread_start(THREADID thread_id)
{
	PIN_GetLock(&Lock, thread_id+1);
	Num_Threads++;
	PIN_ReleaseLock(&Lock);
	ThreadData* tdata = new ThreadData;
	PIN_SetThreadData(Tls_Key, tdata, thread_id);
	if(Redun_Suppress)
	{		
		//read log file if redundancy suppression feature is ON
		if(Run_Num > 1)
		{
			ostringstream os;
			string file = "log";
			os << (thread_id+1);
			file += os.str();//thread id
			file += ".out";
			read_log(file, thread_id);
		}
	}
}

/* ======================================================================================== */
//QDime initialization notification function
//Arguments:	filename2: name of Trace_File2 (QDime execution info file)					
static inline void qdime_init(char *filename2)
{
	/* Read command line knobs*/
	//performance threshold
    threshold.var0 = KnobThresholdVar0.Value();
    //budget percentage
	percentage = KnobBudget.Value();
	//reset budget every period_t_sec seconds
	period_t_sec = KnobPeriod.Value();
	period_t_usec = 0;	
	/* Timer handling*/
	PIN_InterceptSignal(SIGVTALRM,reset_budget,0);    
	PIN_UnblockSignal(SIGVTALRM,TRUE);
    /* Set timer interval*/
	Interval.it_value.tv_sec = period_t_sec;
	Interval.it_value.tv_usec = period_t_usec;//to fire the first time
	Interval.it_interval.tv_sec = period_t_sec;
	Interval.it_interval.tv_usec = period_t_usec;//to repeat the alarm
	setitimer(ITIMER_VIRTUAL, &Interval, NULL); 
    /* to manage large interval*/
	or_period = period_t_sec;
	if(period_t_sec > 1) {
		split_period = period_t_sec - 1;
		period_t_sec = 1;
	}	
	/* Set Budget variable */		
	Budget_Dec = (1.0 * (period_t_sec * sec_to_nsec + period_t_usec * usec_to_nsec)); //forces the instrumentation to start full from the first period.
	/* to manage large interval*/
	if(split_period>0) split_budget = Budget_Dec;
	/*execution info file*/	
	Trace_File2.open (filename2, std::ofstream::out);	
	/* Locate shared memory segment */
	if ((shm_id = shmget(shm_key, sizeof(Metrics), 0666)) < 0) {
    	perror("shmget");
    	exit(1);
	}
  	/* Attach shared memory segment to our data space */
	void* attach;
	if ((attach = shmat(shm_id, NULL, SHM_RDONLY)) == (void *) -1) {
    	perror("shmat");
    	exit(1);
	}
	pmetric = (Metrics*) attach;	
	/* Redundancy Suppression */
	if(KnobRunNum.Value() > 0)
	{	
		Redun_Suppress = true;
		Run_Num = KnobRunNum.Value();
	}
	// Scratch register used to select instrumentation version
	Version_Reg = PIN_ClaimToolRegister();
	//init
	PIN_InitSymbols();	
	PIN_InitLock(&Lock);
}


