package intraprocedural;

import soot.*;
import soot.options.Options;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;

import java.util.Map;

public class MainDriver {
    public static void main(String[] args) {

        /* Process the input arguments from the command line.
         * TODO: 1. support input arguments of path to sink and source files
         *       2. Process the input sink and source files
         */
//        if (args == null) {
//            System.out.println("Please specify folder containing all the classes to analyze");
//            return;
//        }
//        String processDir = args[0];
//        String processDir = "C:\\Users\\Alpac\\Desktop\\McGill\\Course\\ECSE688 Automated Software Testing and Analysis\\Assignments\\PA1\\PA1\\TestPrograms\\ProgramToAnalyzeWithExpectedOutputs";
        String processDir = "C:\\Users\\Alpac\\Desktop\\McGill\\Course\\ECSE688 Automated Software Testing and Analysis\\Assignments\\PA1\\PA1\\TestPrograms\\bytecode";
//        String processClass = "ProgramToAnalyzeWithExpectedOutputs";

        // Set soot classpath
        Options.v().set_soot_classpath(Scene.v().defaultClassPath());

        // Set soot keep line number
        Options.v().set_keep_line_number(true);

        // Add our custom taint analysis to jtp phase of Soot
        Pack jtp = PackManager.v().getPack("jtp");
        jtp.add(new Transform("jtp.instrumenter",
                new IntraTaintTransformer()));

        // Arguments to run Soot. A list of available soot parameters: https://www.sable.mcgill.ca/soot/tutorial/usage/
        String[] sootArgs = new String[] {
                "-p", "jb", "use-original-names:true",
                "-process-dir",
                processDir
        };
        soot.Main.v().run(sootArgs);
    }
}

// The Transformer class as a hook to add the Taint analysis to the jtp phase of Soot
class IntraTaintTransformer extends BodyTransformer {

    @Override
    protected void internalTransform(Body body, String s, Map<String, String> map) {
        // Build the unit graph for the analyzed method
        UnitGraph unitGraph = new BriefUnitGraph(body);

        //Construct an instance of Taint Analysis and conduct the analysis
        new TaintAnalysis(unitGraph);
    }
}
