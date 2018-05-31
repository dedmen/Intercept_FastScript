#include <intercept.hpp>
#include <cstdint>
#include <windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")  //GetModuleInformation

using namespace intercept::types;

uintptr_t placeHookTotalOffs(uintptr_t totalOffset, uintptr_t jmpTo) {
	DWORD dwVirtualProtectBackup;

	/*
	32bit
	jmp 0x123122
	0:  e9 1e 31 12 00          jmp    123123 <_main+0x123123>
	64bit
	FF 25 64bit relative
	*/
#ifdef _M_X64 
	//auto distance = std::max(totalOffset, jmpTo) - std::min(totalOffset, jmpTo);
	// if distance < 2GB (2147483648) we could use the 32bit relative jmp
	VirtualProtect(reinterpret_cast<LPVOID>(totalOffset), 14u, 0x40u, &dwVirtualProtectBackup);
	auto jmpInstr = reinterpret_cast<unsigned char*>(totalOffset);
	auto addrOffs = reinterpret_cast<uint32_t*>(totalOffset + 1);
	*jmpInstr = 0x68;                                                                    //push DWORD
	*addrOffs = static_cast<uint32_t>(jmpTo) /*- totalOffset - 6*/;                      //offset
	*reinterpret_cast<uint32_t*>(totalOffset + 5) = 0x042444C7;                          //MOV [RSP+4],
	*reinterpret_cast<uint32_t*>(totalOffset + 9) = static_cast<uint64_t>(jmpTo) >> 32;  //DWORD
	*reinterpret_cast<unsigned char*>(totalOffset + 13) = 0xc3;                          //ret
	VirtualProtect(reinterpret_cast<LPVOID>(totalOffset), 14u, dwVirtualProtectBackup, &dwVirtualProtectBackup);
	return totalOffset + 14;
#else
	VirtualProtect(reinterpret_cast<LPVOID>(totalOffset), 5u, 0x40u, &dwVirtualProtectBackup);
	auto jmpInstr = reinterpret_cast<unsigned char*>(totalOffset);
	auto addrOffs = reinterpret_cast<unsigned int*>(totalOffset + 1);
	*jmpInstr = 0xE9;
	*addrOffs = jmpTo - totalOffset - 5;
	VirtualProtect(reinterpret_cast<LPVOID>(totalOffset), 5u, dwVirtualProtectBackup, &dwVirtualProtectBackup);
	return totalOffset + 5;
#endif
}


/// interface to functor telling when to interrupt evaluation
class ISuspendCheck {
public:
	virtual ~ISuspendCheck() {}
	virtual bool operator()() const = 0;
};

int BeginContext(game_state &state, game_var_space *vars, bool isUIContext) {
	state.context.push_back(rv_allocator<game_state::game_evaluator>::create_single(vars));
	state.eval = state.context.back();

	state.eval->_errorType = 0;  //EvalOK;
	state.eval->_errorMessage = r_string();
	state.eval->_1 = false;
	state.eval->_2 = isUIContext;

	return state.eval->handle;
}

void EndContext(game_state &state, int handle) {
	if (state.eval->_errorType == 31) return;  //EvalStackOverflow
	if (state.context.size() <= 0) {
		__debugbreak();
		//ErrorMessage("GameState context stack underflow");
		return;
	}
	if (state.context[state.context.size() - 1]->handle != handle) {
		__debugbreak();
		//RptF("Error: Mismatched Begin/EndContexts");
		// but END it in spite of it is not matching pair
	}
	state.context.erase(state.context.end() - 1);
	//_contextStack.CompactIfNeeded(2, 64);
	state.eval = state.context.back();
}

bool IsUIContext(game_state &state) {
	// the code is run as a result of some UI Control Event (VMScript of EvaluateContext knows)
	if (state.eval->_2) return true;

	if (state.current_context)
		return state.current_context->dumm;  //#TODO wrong variable
	return false;
}

enum class executionType {
	Instruction,
	Continue,   
	Done,       
	Yield       
};

#define RESTORE_CONTEXT                                  \
    if (varLevel > minVarLevel) {                        \
        \
varLevel--;  \
/*state.ShowError();*/ /* display error on this level */ \
        \
int gshandle = 0;                                        \
        \
if(!gsHandles.empty()) {                                 \
            gshandle = gsHandles.top();                  \
            gsHandles.pop();                             \
        \
}                                               \
        \
EndContext(state, gshandle);                             \
    \
}


class GameInstructionConst {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0x0a56f03038a03360;
#else
	static const size_t typeIDHash = 0x8c0dbf90;
#endif
};

class GameInstructionVariable {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0xa85b61c9024aa2d8;
#else
	static const size_t typeIDHash = 0xc04f83b1;
#endif
};

class GameInstructionOperator {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0x836a8dd20c3597a3;
#else
	static const size_t typeIDHash = 0x0ac32571;
#endif

};

class GameInstructionFunction {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0xe3939419d62ed014;
#else
	static const size_t typeIDHash = 0x72ff7d2d;
#endif
};

class GameInstructionArray {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0x78c75af7cdcb402d;
#else
	static const size_t typeIDHash = 0x4b5efb7a;
#endif
};

class GameInstructionAssignment {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0xbf6a21dcf26b1790;
#else
	static const size_t typeIDHash = 0xd27a68ec;
#endif
};

class GameInstructionNewExpression {
public:
#ifdef _WIN64
	static const size_t typeIDHash = 0xc1b71c54145040ff;
#else
	static const size_t typeIDHash = 0xc2bb0eeb;
#endif
};
typedef bool(__thiscall *InstrExecFunc)(void *instr, game_state &state, vm_context &t);

static struct {

	InstrExecFunc vt_GameInstructionNewExpression;
	InstrExecFunc vt_GameInstructionConst;
	InstrExecFunc vt_GameInstructionFunction;
	InstrExecFunc vt_GameInstructionOperator;
	InstrExecFunc vt_GameInstructionAssignment;
	InstrExecFunc vt_GameInstructionVariable;
	InstrExecFunc vt_GameInstructionArray;
} oldFunc;

bool __fastcall EvaluateCore(vm_context &vm, game_state &state, int minVarLevel, const ISuspendCheck &funcInterrupt) {  //
	//auto tid = typeid(funcInterrupt).raw_name();
	auto tidh = typeid(funcInterrupt).hash_code();
	bool noInterrupt = tidh == 0xe2aa4b3f32d37939;
	stack_array<int, rv_allocator_local<int, 64>> gsHandles;

	int varLevel = minVarLevel;
	while (true) {
		int level = vm.callstack.size() - 1;
		if (level < 0) {
			// restore context
			RESTORE_CONTEXT
				return true;
		}

		if (vm.exception_state) {  // handle exception
			while (level >= 0) {
				if (vm.callstack[level]->someEH(&state)) break;
				// level up
				RESTORE_CONTEXT
					vm.callstack.resize(level);
				level--;
			}
			if (level < 0) {
				state.eval->_errorType = 30;//EvalUnhandledException
				state.eval->_errorMessage = vm.exception_value;

			}
			if (state.eval->_errorType != 0) {//EvalOK
											  // end evaluation
											  // restore context
				RESTORE_CONTEXT
					return true;
			}
			//Assert(!_exceptionThrown);
			if (vm.exception_state) __debugbreak();
			level = vm.callstack.size() - 1;  // level can be changed in OnException
		} else if (vm.break_) {             // handle break
			while (level >= 0) {
				if (vm.callstack[level]->someEH2(&state)) break;
				// level up
				RESTORE_CONTEXT
					vm.callstack.resize(level);
				level--;
			}
			if (level < 0) {
				// restore context
				RESTORE_CONTEXT
					return true;
			}
			if (state.eval->_errorType != 0) {  //EvalOK
												// end evaluation
												// restore context
				RESTORE_CONTEXT
					return true;
			}
			//Assert(!_break);
			if (vm.break_) __debugbreak();
			level = vm.callstack.size() - 1;  // level can be changed in OnBreak
		}

		// check a new call stack level
		while (level > varLevel) {
			varLevel++;
			int gshandle = BeginContext(state, &vm.callstack[varLevel]->_varSpace, IsUIContext(state));
			gsHandles.push(gshandle);
		}

		vm.callstack[level]->on_before_exec();

		executionType rec;

		game_instruction *instr = vm.callstack[level]->next(reinterpret_cast<int &>(rec), &state);

		switch (rec) {
			case executionType::Instruction: {
				if (!instr) __debugbreak();
				//Assert(instr);

				// FIX: set what _stack size is expected after the instruction
				// when break occurs during processing, we need to recover _stack to this size
				vm.callstack[level]->_stackLast = (vm.scriptStack.size() + instr->stack_size(&vm));

				vm.sdocpos = instr->sdp;







				bool instrResult = false;

				auto typeHash = typeid(*instr).hash_code();

				switch (typeHash) {
					case GameInstructionNewExpression::typeIDHash: {  //GameInstructionNewExpression
						instrResult = oldFunc.vt_GameInstructionNewExpression(instr, state, vm);
					} break;
					case GameInstructionConst::typeIDHash: {  //GameInstructionConst
						instrResult = oldFunc.vt_GameInstructionConst(instr, state, vm);
					} break;
					case GameInstructionFunction::typeIDHash: {  //GameInstructionFunction
						instrResult = oldFunc.vt_GameInstructionFunction(instr, state, vm);
					} break;
					case GameInstructionOperator::typeIDHash: {  //GameInstructionOperator
						instrResult = oldFunc.vt_GameInstructionOperator(instr, state, vm);
					} break;
					case GameInstructionAssignment::typeIDHash: {  //GameInstructionAssignment
						instrResult = oldFunc.vt_GameInstructionAssignment(instr, state, vm);
					} break;
					case GameInstructionVariable::typeIDHash: {  //GameInstructionVariable
						instrResult = oldFunc.vt_GameInstructionVariable(instr, state, vm);
					} break;
					case GameInstructionArray::typeIDHash: {  //GameInstructionArray
						instrResult = oldFunc.vt_GameInstructionArray(instr, state, vm);
					} break;
					default: __debugbreak();
				}
				//instr->exec(state, vm)
				if (instrResult) {
					// end evaluation
					// restore context
					RESTORE_CONTEXT
						return true;
				} else {
					if (noInterrupt) break;
					// check if the external conditions to yield script execution was met
					bool FI = funcInterrupt();
					bool interrupt = instr->bfunc() && FI;  // &&funcInterrupt();
					if (!interrupt) break;
					// continue to RECYield otherwise
				}
			}
			case executionType::Yield:
				if (vm.scheduled) {
					// restore context
					RESTORE_CONTEXT
						return false;  // done for this simulation step
				}
				__debugbreak();
				//RptF("Suspending not allowed in this context");
				//state.SetError(EvalGen);
				//state.ShowError();
				// error recovery
				//state.SetError(EvalOK);
				// continue

			case executionType::Done:
				while (varLevel > level - 1 && varLevel > minVarLevel) {
					varLevel--;
					//state.ShowError();  // display error on this level
					int gshandle = 0;
					if (!gsHandles.empty()) {
						gshandle = gsHandles.top();
						gsHandles.pop();
					}
					EndContext(state, gshandle);
				}
				vm.callstack.resize(level);
				break;  // continue on the calling level
			case executionType::Continue:
				break;
		}
	}
}

extern "C" void evalIngressFnc();

extern "C" {
	uintptr_t evalIngress = reinterpret_cast<uintptr_t>(&EvaluateCore);
}

void intercept::pre_start() {
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(NULL);
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	auto engineBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
	auto engineSize = static_cast<uintptr_t>(modInfo.SizeOfImage);

	uintptr_t placeHookTotalOffs(uintptr_t totalOffset, uintptr_t jmpTo);


	auto findInMemoryPattern = [engineBase, engineSize](const char *pattern, const char *mask, uintptr_t offset = 0) {
		const uintptr_t base = engineBase;
		const uintptr_t size = engineSize;

		const uintptr_t patternLength = static_cast<uintptr_t>(strlen(mask));

		for (uintptr_t i = 0; i < size - patternLength; i++) {
			bool found = true;
			for (uintptr_t j = 0; j < patternLength; j++) {
				found &= mask[j] == '?' || pattern[j] == *reinterpret_cast<char *>(base + i + j);
				if (!found)
					break;
			}
			if (found)
				return base + i + offset;
		}
		return static_cast<uintptr_t>(0x0u);
	};

	auto p1 = findInMemoryPattern(
		"\x48\x8B\xC4\x44\x89\x40\x18\x48\x89\x48\x08\x55\x53\x48\x8D\xA8\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x89\x70\x10\x48\x89\x78\xE8\x4C\x89\x60\xE0\x4C\x89\x68\xD8\x4C\x89\x70\xD0\x4C\x89\x78\xC8\x44\x8B\x79\x10\x41\x8B\xF8\x48\x8B\xDA\x41\xFF\xCF\x4C\x8B\xE9\xC6\x45\x54\x00\x48\xC7\x44\x24\x00\x00\x00\x00\x00\xC7\x45\x00\x00\x00\x00\x00\xC7\x44\x24\x00\x00\x00\x00\x00\x45\x8B\xF0\x0F\x88\x00\x00\x00\x00\x0F\x1F\x84\x00\x00\x00\x00\x00\x41\x80\xBD\x00\x00\x00\x00\x00\x49\x63\xF7\x0F\x84\x00\x00\x00\x00\x48\x8D\x34\xF5\x00\x00\x00\x00\x0F\x1F\x80\x00\x00\x00\x00\x49\x8B\x45\x08\x48\x8B\xD3\x48\x8B\x0C\x06\x48\x8B\x01\xFF\x50\x20\x84\xC0\x0F\x85\x00\x00\x00\x00", "xxxxxxxxxxxxxxxx????xxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?????xx?????xxx?????xxxxx????xxxx????xxx?????xxxxx????xxxx????xxx????xxxxxxxxxxxxxxxxxxxxx????"
	);

	placeHookTotalOffs(p1, (uintptr_t) &evalIngressFnc);

	static struct vtables {
		void **vt_GameInstructionNewExpression;
		void **vt_GameInstructionConst;
		void **vt_GameInstructionFunction;
		void **vt_GameInstructionOperator;
		void **vt_GameInstructionAssignment;
		void **vt_GameInstructionVariable;
		void **vt_GameInstructionArray;
	} GVt;
	auto iface = intercept::client::host::request_plugin_interface("sqf_asm_devIf", 1);
	if (iface) {
		GVt = *static_cast<vtables *>(*iface);

		oldFunc.vt_GameInstructionConst = (InstrExecFunc) GVt.vt_GameInstructionConst[3];
		oldFunc.vt_GameInstructionVariable = (InstrExecFunc) GVt.vt_GameInstructionVariable[3];
		oldFunc.vt_GameInstructionOperator = (InstrExecFunc) GVt.vt_GameInstructionOperator[3];
		oldFunc.vt_GameInstructionFunction = (InstrExecFunc) GVt.vt_GameInstructionFunction[3];
		oldFunc.vt_GameInstructionArray = (InstrExecFunc) GVt.vt_GameInstructionArray[3];
		oldFunc.vt_GameInstructionAssignment = (InstrExecFunc) GVt.vt_GameInstructionAssignment[3];
		oldFunc.vt_GameInstructionNewExpression = (InstrExecFunc) GVt.vt_GameInstructionNewExpression[3];
	}

}


int intercept::api_version() { //This is required for the plugin to work.
	return 1;
}