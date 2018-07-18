//===-- PrivacyScopeChecker.cpp -----------------------------------------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Defines a checker for privacy leakage of function module.
// If there exist a reverse function which leaks the input from output, this checker 
// will warn the user
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>

using namespace clang;
using namespace ento;

/*
class TestState{
private:
	enum Kind {On, Off} K;
public:
	TestState(unsigned InK): K((Kind) Ink){}
	Void Profile(llvm::FoldingSetNodeID &ID) const{
		ID.AddInteger(K);
	}
};
*/

//check::PostCall,
namespace {

class PrivacyScopeChecker : public Checker <check::EndAnalysis,
											check::PreStmt<ReturnStmt>,
											check::Bind,
											check::BeginFunction,
											check::EndFunction> {
	mutable IdentifierInfo *IIturnOn;
	//OwningPtr<BugType> ConstBugType;
	std::unique_ptr<BugType> ImplicitBugType;
	void initIdentifierInfo(ASTContext &Ctx) const;
	//void reportConst(const CallEvent &Call, CheckerContext &C) const;
	void reportImplicit(SymbolRef FileDescSym,
                        const CallEvent &Call,
                        CheckerContext &C) const;
public:
	PrivacyScopeChecker();
	//void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
	void checkEndAnalysis(ExplodedGraph &G,
                         BugReporter &BR,
                         ExprEngine &Eng) const;
	void checkPreStmt(const ReturnStmt *RS,
                      CheckerContext &C) const;
	void checkBind(SVal Loc, SVal Val, const Stmt *S,
                      CheckerContext &C) const;
	void checkBeginFunction(CheckerContext &Ctx) const {}
	void checkEndFunction(const ReturnStmt *RS, CheckerContext &Ctx) const;
};

}


//(Name, Key, Value)
//REGISTER_MAP_WITH_PROGRAMSTATE(RS, int, TestState)

PrivacyScopeChecker::PrivacyScopeChecker() {
	// Init bug types
	ImplicitBugType.reset(new BugType(this, "Implicit","Implicit leakage"));
}

   /// Called on binding of a value to a location.
   ///
   /// \param Loc The value of the location (pointer).
   /// \param Val The value which will be stored at the location Loc.
   /// \param S   The bind is performed while processing the statement S.
   ///
   /// check::Bind
void PrivacyScopeChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                      CheckerContext &C) const{
	
}

   /// Pre-visit the Statement.
   ///
   /// The method will be called before the analyzer core processes the
   /// statement. The notification is performed for every explored CFGElement,
   /// which does not include the control flow statements such as IfStmt. The
   /// callback can be specialized to be called with any subclass of Stmt.
   ///
   /// See checkBranchCondition() callback for performing custom processing of
   /// the branching statements.
   ///
   /// check::PreStmt<ReturnStmt>
void PrivacyScopeChecker::checkPreStmt(const ReturnStmt *RS,
                                             CheckerContext &C) const {
	ProgramStateRef state = C.getState();

	const Expr *RetE = RS->getRetValue();
	if (!RetE)
	return;

	SVal V = C.getSVal(RetE);

	// for (SymExpr::symbol_iterator si = V.symbol_begin(),
	//                           se = V.symbol_end(); si != se; ++si){
	// 	if(si == se){
	// 		break;
	// 	}
	// }


	if (V.isConstant()){
		ExplodedNode *N = C.generateErrorNode(state);
	}

	
}

   /// Called when the analyzer core starts analyzing a function,
   /// regardless of whether it is analyzed at the top level or is inlined.
   ///
   /// check::BeginFunction
   void PrivacyScopeChecker::checkBeginFunction(CheckerContext &Ctx) const {

   }
 
   /// Called when the analyzer core reaches the end of a
   /// function being analyzed regardless of whether it is analyzed at the top
   /// level or is inlined.
   ///
   /// check::EndFunction
   void PrivacyScopeChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &Ctx) const {

   }

   /// Called after all the paths in the ExplodedGraph reach end of path
   /// - the symbolic execution graph is fully explored.
   ///
   /// This callback should be used in cases when a checker needs to have a
   /// global view of the information generated on all paths. For example, to
   /// compare execution summary/result several paths.
   /// See IdempotentOperationChecker for a usage example.
   ///
   /// check::EndAnalysis

void PrivacyScopeChecker::checkEndAnalysis(ExplodedGraph &G,
                         				   BugReporter &BR,
                         				   ExprEngine &Eng) const{
	const Decl *D = nullptr;
	CFG *C = nullptr;
	ParentMap *PM = nullptr;
	const LocationContext *LC = nullptr;
	for (ExplodedGraph::node_iterator I = G.nodes_begin(), E = G.nodes_end();
	  I != E; ++I) {
	const ProgramPoint &P = I->getLocation();
	LC = P.getLocationContext();
	// Save the CFG if we don't have it already
	if (!C)
	  C = LC->getAnalysisDeclContext()->getUnoptimizedCFG();
	}

}


   /// Allows modifying SymbolReaper object. For example, checkers can explicitly
   /// register symbols of interest as live. These symbols will not be marked
   /// dead and removed.
   ///
   /// check::LiveSymbols

   /// Handles assumptions on symbolic values.
   ///
   /// This method is called when a symbolic expression is assumed to be true or
   /// false. For example, the assumptions are performed when evaluating a
   /// condition at a branch. The callback allows checkers track the assumptions
   /// performed on the symbols of interest and change the state accordingly.
   ///
   /// eval::Assume

   /// Evaluates function call.
   ///
   /// The analysis core threats all function calls in the same way. However, some
   /// functions have special meaning, which should be reflected in the program
   /// state. This callback allows a checker to provide domain specific knowledge
   /// about the particular functions it knows about.
   ///
   /// \returns true if the call has been successfully evaluated
   /// and false otherwise. Note, that only one checker can evaluate a call. If
   /// more than one checker claims that they can evaluate the same call the
   /// first one wins.
   ///
   /// eval::Call

   /// Called whenever a symbol becomes dead.
   ///
   /// This callback should be used by the checkers to aggressively clean
   /// up/reduce the checker state, which is important for reducing the overall
   /// memory usage. Specifically, if a checker keeps symbol specific information
   /// in the sate, it can and should be dropped after the symbol becomes dead.
   /// In addition, reporting a bug as soon as the checker becomes dead leads to
   /// more precise diagnostics. (For example, one should report that a malloced
   /// variable is not freed right after it goes out of scope.)
   ///
   /// \param SR The SymbolReaper object can be queried to determine which
   ///           symbols are dead.
   ///
   /// check::DeadSymbols

void PrivacyScopeChecker::reportImplicit(SymbolRef FileDescSym,
                                         const CallEvent &Call,
                                         CheckerContext &C) const{
	ExplodedNode *ErrNode = C.generateErrorNode();
	if (!ErrNode)
		return;
	auto R = llvm::make_unique<BugReport>(*ImplicitBugType,
    "Implicit leakage", ErrNode);
	R->addRange(Call.getSourceRange());
	R->markInteresting(FileDescSym);
	C.emitReport(std::move(R));
}


/*
void PrivacyScopeChecker::reportConst(const CallEvent &Call, CheckerContext &C) const{
	ExplodedNode *ErrNode = C.generateSink();
	if (!ErrNode)
		return;
	BugReport *R = new BugReport(*ConstBugType, "Constant propagation leakage", ErrNode);
	R->addRange(Call.getSourceRange());
	C.emitReport(R);
}
*/


void ento::registerPrivacyScopeChecker(CheckerManager &mgr) {
  mgr.registerChecker<PrivacyScopeChecker>();
}
