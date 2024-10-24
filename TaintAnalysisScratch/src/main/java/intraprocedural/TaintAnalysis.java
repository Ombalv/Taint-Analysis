package intraprocedural;


import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ArraySparseSet;
import soot.toolkits.scalar.FlowSet;
import soot.toolkits.scalar.ForwardFlowAnalysis;
import soot.util.Chain;
import soot.tagkit.LineNumberTag;


import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.List;

/*
 * The class extending ForwardFlowAnalysis. This is where you need to implement your taint analysis
 * TODO:
 *  Use a proper data structure for the program states so that you can support multiple taint sources and report the location of the taint source at the sinks.
 *  Replace FlowSet<Value> with the data structure you chose. You will also need to change the type of several parameters and return values of the methods
 *
 */

class TaintStruct{
    public HashSet<Value> value_set;
    public Unit TaintSource_unit;

    //constructor
    public TaintStruct(HashSet<Value> value_set, Unit TaintSource_unit){
        this.value_set = value_set;
        this.TaintSource_unit = TaintSource_unit;
    }
    public HashSet<Value> getValue(){
        return value_set;
    }
    public Unit getTaintSource(){
        return TaintSource_unit;
    }
}


public class TaintAnalysis extends ForwardFlowAnalysis<Unit, FlowSet<TaintStruct>> {
    public Set<String> sources = new HashSet<>();
    public Set<String> sinks = new HashSet<>();
    public UnitGraph unitGraph;

    public void readSource_and_Sink(){
        // parse the source and sink from the given two txt file
        try {
            sources.addAll(Files.readAllLines(Paths.get("C:\\Users\\Alpac\\Desktop\\McGill\\Course\\ECSE688 Automated Software Testing and Analysis\\Assignments\\PA1\\PA1\\TestPrograms\\InputFiles\\source.txt")));
            sinks.addAll(Files.readAllLines(Paths.get("C:\\Users\\Alpac\\Desktop\\McGill\\Course\\ECSE688 Automated Software Testing and Analysis\\Assignments\\PA1\\PA1\\TestPrograms\\InputFiles\\sink.txt")));
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    //Constructor of the class
    public TaintAnalysis(DirectedGraph<Unit> graph) {
        super(graph);
        this.unitGraph = (UnitGraph) graph;
        //get Source and Sinks methods from the TestPrograms/InputFiles/source.txt and TestPrograms/InputFiles/sink.txt
        readSource_and_Sink();
        //doAnalysis will perform the analysis
        doAnalysis();

        // Print out the analysis results
        UnitGraph unitGraph = (UnitGraph) graph;

        // The unit chain that can iterate over all the units in the unit graph
        Chain<Unit> unitChain = unitGraph.getBody().getUnits();
        for (Unit unit : unitChain) {
//            System.out.println("unit: "+unit);
            // Cast the unit to Stmt (statement)
            Stmt stmt = (Stmt) unit;
            // Get the IN state of unit after the analysis
            // TODO: You'll need to change the type of inState to the one you chose to represent the program states
//            FlowSet<Value> inState = this.getFlowBefore(unit);
            FlowSet<TaintStruct> inState = this.getFlowBefore(unit);
            // Check if unit is a sink
            // TODO: Support reading the list of sinks from a file, and check whether unit is a sink.
            if (stmt.containsInvokeExpr() &&
                    sinks.contains(stmt.getInvokeExpr().getMethodRef().getSignature())) {
//                stmt.getInvokeExpr().getMethodRef().getSignature()).equals("<io.github.liliweise.Source: void sink(int)>")

                //Get the values used in unit
                Set<Value> usedValues = new HashSet<>();
                for (ValueBox usedValueBoxes : unit.getUseBoxes()) {
                    usedValues.add(usedValueBoxes.getValue());
                }

                // Check whether any of the used variables are tainted.
                for (TaintStruct taintStruct : inState) {
//                for (Value taintedValue : inState) {
                    for(Value value : taintStruct.getValue()){
                        if (usedValues.contains(value)) {
//                    if (usedValues.contains(taintedValue)) {
                            //If a variable is tainted, report a leak
                            //TODO: Change the output to report both the taint source and the sink that causes the leak
                            Unit Source_Unit = taintStruct.getTaintSource();
                            Unit Sink_Unit = unit;
                            LineNumberTag Source_Unit_lineNumberTag = (LineNumberTag) Source_Unit.getTag("LineNumberTag");
                            LineNumberTag Sink_Unit_lineNumberTag = (LineNumberTag) Sink_Unit.getTag("LineNumberTag");
                            System.out.println("——————————————————");
                            System.out.println("Found a Leak in " + unitGraph.getBody().getMethod().getSignature());
                            System.out.println("Source: line " + Source_Unit_lineNumberTag + ": " + taintStruct.getTaintSource());
                            System.out.println("Leak: line " + Sink_Unit_lineNumberTag + ": " + unit);
//                        System.out.println("Leak at " + unit);
                        }
                    }
                }
            }
        }
    }

    @Override
    protected void flowThrough(FlowSet<TaintStruct> inState, Unit unit, FlowSet<TaintStruct> outState) {
        /*
        * TODO: implement the transfer functions here
        *  This method is invoked for every statement in a method.
        *  The statement being analyzed is the parameter "unit"
        *  Remember to handle implicit flows
        * */
        // Default Behavior, copy inState to outState
//        System.out.println("inState: " + inState);
        inState.copy(outState);

        // convert unit from Unit type to Stmt type for detecting the particular operation of each unit
        Stmt stmt = (Stmt) unit;

//        System.out.println("Stmt type: " + stmt.getClass().getName());

        // determine this unit whether is an Assignment Unit(assign value to a variable)
        if(stmt instanceof AssignStmt){
//            System.out.println("get into the AssignStmt");
            AssignStmt assignStmt = (AssignStmt) stmt;

            // get the operation from right and left side of "="
            Value right_Op = assignStmt.getRightOp();
            Value left_Op = assignStmt.getLeftOp();

            // determine whether the right operation is calling a function of Source
            if(right_Op instanceof InvokeExpr) {
//                System.out.println("right_Op is InvokeExpr");
                InvokeExpr invokeExpr = (InvokeExpr) right_Op;
                // determine whether the invokeExpr on the right side is the Source
                if(isTaintSource(invokeExpr)){
                    HashSet<Value> value_set = new HashSet<>();
                    value_set.add(left_Op);
                    TaintStruct taintStruct = new TaintStruct(value_set, unit);
                    outState.add(taintStruct);
                    }
                }

            // determine whether the right operation is a binary operation expression
            else if(right_Op instanceof BinopExpr) {
                BinopExpr binopExpr = (BinopExpr) right_Op;
                Value op_1 = binopExpr.getOp1();
                Value op_2 = binopExpr.getOp2();

                for (TaintStruct taintStruct : outState) {
                    if ((taintStruct.getValue().contains(op_1)) || (taintStruct.getValue().contains(op_2))) {
                        taintStruct.value_set.add(left_Op);
                    } else {
                        taintStruct.value_set.remove(left_Op);
                    }
                }
            }
        }

        else if (stmt instanceof IfStmt){
            handle_implicit_flows(inState, unit, outState);
        }
    }

    @Override
    protected FlowSet<TaintStruct> newInitialFlow() {
        // Initialize each program state
        // TODO: Initialize your own data structure
        return new ArraySparseSet<TaintStruct>();
    }

    @Override
    protected void merge(FlowSet<TaintStruct> out1, FlowSet<TaintStruct> out2, FlowSet<TaintStruct> in) {
        // Merge program state out1 and out2 into in
        // TODO: Change the merge function accordingly for your data structure
        out1.union(out2, in);
    }

    @Override
    protected void copy(FlowSet<TaintStruct> src, FlowSet<TaintStruct> dest) {
        // Copy from src to dest
        // TODO: Change the copy function accordingly for your data structure
        src.copy(dest);
    }

    @Override
    protected FlowSet<TaintStruct> entryInitialFlow() {
        // Initialize the initial program state
        // TODO: Initialize your own data structure
        return new ArraySparseSet<TaintStruct>();
    }

    private boolean isTaintSource(InvokeExpr invokeExpr) {
        String invokeExpr_signature = invokeExpr.getMethodRef().getSignature();
        return (sources.contains(invokeExpr_signature));
    }

    private boolean isTaintCondition(Value condition, TaintStruct taintStruct) {
        if (condition instanceof BinopExpr){
            BinopExpr conditionBinopExpr = (BinopExpr) condition;
            Value op_1 = conditionBinopExpr.getOp1();
            Value op_2 = conditionBinopExpr.getOp2();
            return (taintStruct.getValue().contains(op_1) || taintStruct.getValue().contains(op_2));
        }
        return false;
    }

    void handle_implicit_flows(FlowSet<TaintStruct> inState, Unit unit, FlowSet<TaintStruct> outState) {
        IfStmt ifStmt = (IfStmt) unit;

        Value condition = ifStmt.getCondition();
        for(TaintStruct taintStruct : outState){
            if(isTaintCondition(condition, taintStruct)){
                // get the next Unit if condition is true
                Unit trueBranchUnit = ifStmt.getTarget();
                Unit falseBranchUnit = null;
                // get the next unit if condition is not satisfied
                List<Unit> successors = unitGraph.getSuccsOf(ifStmt);
                if (!(successors.isEmpty())){
                    falseBranchUnit = successors.get(0);
                }

                Unit end_unit = FindConditonEnd(trueBranchUnit, falseBranchUnit);
                propagateTainttoBranch(trueBranchUnit, taintStruct, end_unit);
                propagateTainttoBranch(falseBranchUnit, taintStruct, end_unit);
            }
        }
    }

    void propagateTainttoBranch(Unit StartUnit, TaintStruct taintStruct, Unit EndUnit){
        Unit currentUnit = StartUnit;
        while (!(currentUnit instanceof IfStmt) && currentUnit != null && currentUnit!=EndUnit){
            if(currentUnit instanceof AssignStmt){
                AssignStmt assignStmt = (AssignStmt) currentUnit;
                taintStruct.value_set.add(assignStmt.getLeftOp());
            }
            List<Unit> successors = unitGraph.getSuccsOf(currentUnit);
            if(successors.isEmpty()) {
                currentUnit = null;
            }
            else {
                currentUnit = successors.get(0);
            }
        }
    }

    // find the end unit of condition statements
    Unit FindConditonEnd(Unit TrueBranchStart, Unit FalseBranchStart){
        Set<Unit> VisitedUnitTrue = new LinkedHashSet<>();
        Set<Unit> VisitedUnitFalse = new LinkedHashSet<>();
        // tracking true branch
        Unit CurrentTrue = TrueBranchStart;
        while(CurrentTrue != null) {
            VisitedUnitTrue.add(CurrentTrue);
            List<Unit> successorsTrue = unitGraph.getSuccsOf(CurrentTrue);
            if (!successorsTrue.isEmpty()) {
                CurrentTrue = successorsTrue.get(0);
            } else {
                CurrentTrue = null;
            }
        }
        // tracking false branch
        Unit CurrentFalse = FalseBranchStart;
        while(CurrentFalse != null) {
            VisitedUnitFalse.add(CurrentFalse);
            List<Unit> successorsFalse = unitGraph.getSuccsOf(CurrentFalse);
            if (!successorsFalse.isEmpty()) {
                CurrentFalse = successorsFalse.get(0);
            } else {
                CurrentFalse = null;
            }
        }
        for(Unit falseunit : VisitedUnitFalse){
            for(Unit trueunit: VisitedUnitTrue){
                if(falseunit == trueunit){
                    return falseunit;
                }
            }
        }
        return null;
    }
}