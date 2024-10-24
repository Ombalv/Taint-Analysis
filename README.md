# Taint Analysis
 Implement Taint Analysis with Soot

## Prerequisite
Make sure that you have already successfully installed Java8 and IntelliJ, and they can run on your PC/laptop.
### Step 1 Load the pom.xml file by Maven
The pom.xml file is in the directory of “PA1/TaintAnalysisScratch/pom.xml”. This is a file given by the instructor and you can use Maven to load it to easily import the “Soot”. The detailed step includes finding the pom.xml file in the right side of directory in the IntelliJ, right clicking that file and choosing “Add as Maven Project”. Then you will see that Soot has been loaded for this project.
### Step 2 Rewrite the directory of the code to analyze
Find the string variable `processDir` in the “PA1\TaintAnalysisScratch\src\main\java\intraprocedural\MainDriver.java” It is in line 23. And replacing the value with the absolute directory of “//PA1//TestPrograms//bytecode” in your system.
### Step 3 Rewrite the directory of the source and sink API
Find two lines of code in the “PA1/TaintAnalysisScratch/src/main/java/intraprocedural/TaintAnalysis.java” in line 59 and 60. And correspondingly replacing the directory with the absolute directory of “PA1\\TestPrograms\\InputFiles\\source.txt” and “PA1\\TestPrograms\\InputFiles\\sink.txt” in your system.
### Step 4 Add source root
In IntelliJ, right clicking the directory of “PA1\TaintAnalysisScratch\src\main\java”, and put your mouse on the “Mark Directory as” and select “Sources Root”. You will see it becomes blue.
### Step 5 Run code
Run ‘MainDriver’, and you will see the result of taint analysis printed out in the bottom.

## Detailed implementation
### In MainDriver.java
I maintain all the content in this file, and only put one more line of code which is `Options.v().set_keep_line_number(true);` in the main function to set Soot to keep the line number of each unit it has analyzed for printing the line information as the requirement.
### In TaintAnalysis.java
Here is the implementation of how I leverage Soot to do taint analysis.
#### TaintStruct
First of all, I defined a new data structure named `TaintStruct` for the program states so that my program can support multiple taint sources and report the location of the taint source at corresponding sinks. A `TaintStruct` includes a `HashSet<Value>` type `value_set` variable as the taint set for outstate and instate of a unit and a corresponding `Unit` type `TaintSource_unit` variable to record the Source of the tainted values inside the `value_set`. Additionally, I defined two functions, `getValue()` and `getTaintSource()` to access the `TaintSource_unit` and `value_set` variables in the `TaintStruct`. Also, I replaced all the `FlowSet<Value>` with `FlowSet<TaintStruct>` in this skeleton.
#### readSource_and_Sink()
This is an additional function I defined inside the given class `TaintAnalysis`. It is used to read the Source API and Sink API from two provided .txt files and separately store them in `sources` and `sinks` variables for later analysis.
#### Transfer function: flowthrough(FlowSet<TaintStruct> inState, Unit unit, FlowSet<TaintStruct> outState)
This transfer function `flowthrough` is the core part of our taint analyzer and invoked for every statement. It plays the role of processing each statement analyzed as the parameter “unit” by Soot and identifying tainted variables and recording them in the `outState ` variable. Firstly, I copy the `inState` to `outState ` as the default step at the beginning of transfer function. I convert `unit` to Stmt type variable `stmt` for easier operation. Then, I made an “if”, “else if” condition statement to identify whether the statement my program is analyzing is an “Assignment statement” or an “If statement”. 
If the analyzed statement is an “Assignment statement”. My program will extract the variable on the left hand of “=” and the operation on the right hand separately. After that, my program will identify whether the operation on the right hand is an “Invoke expression”, like invoking a function or data structure and assigning it to the variable on the left hand or the operation on the right hand is an “Binary operation expression”, like “a+1” or “a+b”. For the former one, my program will identify whether the invoked function or data structure is a “Source” or not, according to the sources read from the Source API. If it is a “Source”, my program will create a new TaintStruct variable and assign the variable on the left hand and the current `unit` to the `value_set` and ` TaintSource_unit` of this TaintStruct type variable, and finally add this newly created TaintStruct type variable to the `outState` variable. For the later one, my program will identify whether the operation on the right hand contains tainted variables. If it contains tainted variable, my program will add the variable on the left hand to the `value_set` for all the TaintStruct variables in the `outState` whose `value_set` containing that tainted variable. However, if the operation on the right hand does not contain any tainted variables, which means the variable on the left hand becomes untainted, my program will remove the variable on the left hand from all the `value_set` for all the TaintStruct variables in the `outState` whose `value_set` containing the variable on the left hand.
If the analyzed statement is an “If statement”, my program will call a “handle_implicit_flows” function, which successfully handled the implicit flows and will be demonstrated in detail later.
#### Solution to handle implicit flows: handle_implicit_flows(FlowSet<TaintStruct> inState, Unit unit, FlowSet<TaintStruct> outState)
In this function, the implicit flows are successfully handled. First of all, my program extracts the condition from the “if statement”, and then my program will identify whether the condition contains taint values. Once it contains taint values, regarding the over-approximation rule, all the variables within the branches of the condition statement will be seemed as tainted. Here I defined a new “propagateTainttoBranch” function to accomplish this kind of taint propagation caused by tainted conditions. And all the variables within the branches under tainted condition will be put into the `value_set` for all the TaintStruct variables whose `value_set` containing the tainted variable in the condition in the `outState`.
#### FindConditonEnd()
It is worth mentioning that the propagation is not endless, and it is only within the branches of the condition statement. Hence, we need to find out the end of the branches under the condition statement. However, there is not an explicit function in Soot. So, I defined this function “FindConditionEnd” to return the end unit of the branches under a condition statement. The way of how it finds the end unit is to get the set of successor units of each branch unit in order, and the first common unit these sets of successor units share is the merge unit which is also the end unit. I used LinkedHashSet type instead of HashSet type to create these sets of successor units here since we need the elements in the set to be in order, and the elements in the HashSet are not in order which took me a lot of time to debug.