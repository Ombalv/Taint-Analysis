import secret.Input;
import sensitive.Sink;
import sensitive.Source;

public class ProgramToAnalyzeWithExpectedOutputs {
    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void simpleFlow1()>
     * Source: line 14: x = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 17: staticinvoke <sensitive.Sink: void sink(int)>(z)
     */
    public void simpleFlow1(){
        int x = Source.source();
        int y = 8;
        int z = x + y;
        Sink.sink(z);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void simpleFlow2()>
     * Source: line 28: a = staticinvoke <sensitive.Source: int sensitiveInfo()>()
     * Leak: line 32: staticinvoke <sensitive.Sink: void leak(int)>(c)
     */
    public void simpleFlow2() {
        int a = Source.sensitiveInfo();
        int b = Source.benign();
        int c = a + 9;
        int d = b + 9;
        Sink.leak(c);
        Sink.leak(d);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void simpleFlow3()>
     * Source: line 44: a = staticinvoke <sensitive.Source: int sensitiveInfo()>()
     * Leak: line 48: staticinvoke <sensitive.Sink: void leak(int)>(a)
     */
    public void simpleFlow3() {
        int a = Source.sensitiveInfo();
        int b = a + 9;
        Sink.use(b);
        b = 10;
        Sink.leak(a);
        Sink.leak(b);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void longTaintChain()>
     * Source: line 60: a = staticinvoke <sensitive.Source: int sensitiveInfo()>()
     * Leak: line 65: staticinvoke <sensitive.Sink: void leak(int)>(e)
     * */
    public void longTaintChain() {
        int a = Source.sensitiveInfo();
        int b = a + 2;
        int c = a * b;
        int d = c + 5;
        int e = d + 6;
        Sink.leak(e);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint1()>
     * Source: line 80: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 84: staticinvoke <secret.Input: void send(int)>(c)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint1()>
     * Source: line 81: b = staticinvoke <secret.Input: int sensitiveInfo()>()
     * Leak: line 85: staticinvoke <sensitive.Sink: void sink(int)>(d)
     * */
    public void multiTaint1() {
        int a = Source.source();
        int b = Input.sensitiveInfo();
        int c = a + 1;
        int d = b + 1;
        Input.send(c);
        Sink.sink(d);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint2()>
     * Source: line 101: b = staticinvoke <secret.Input: int sensitiveInfo()>()
     * Leak: line 103: staticinvoke <sensitive.Sink: void leak(int)>(c)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint2()>
     * Source: line 100: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 103: staticinvoke <sensitive.Sink: void leak(int)>(c)
     */
    public void multiTaint2() {
        int a = Source.source();
        int b = Input.sensitiveInfo();
        int c = a + b;
        Sink.leak(c);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint3()>
     * Source: line 118: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 122: staticinvoke <sensitive.Sink: void sink(int)>(c)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaint3()>
     * Source: line 119: b = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 123: staticinvoke <sensitive.Sink: void sink(int)>(d)
     */
    public void multiTaint3() {
        int a = Source.source();
        int b = Source.source();
        int c = a + 1;
        int d = b + 1;
        Sink.sink(c);
        Sink.sink(d);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void implicitFlow1()>
     * Source: line 138: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 147: staticinvoke <sensitive.Sink: void leak(int)>(c#3)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void implicitFlow1()>
     * Source: line 138: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 148: staticinvoke <sensitive.Sink: void sink(int)>(d)
     */
    public void implicitFlow1() {
        int a = Source.source();
        int c = Source.benign();
        int d = 0;
        if (a > 2) {
            c = 9;
        } else {
            c = 10;
            d = 11;
        }
        Sink.leak(c);
        Sink.sink(d);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void implicitFlow2()>
     * Source: line 159: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 169: staticinvoke <sensitive.Sink: void leak(int)>(d)
     */
    public void implicitFlow2() {
        int a = Source.source();
        int c = 0, d = 2;
        if (a > 2) {
            c = 9;
            d = 10;
        }
        Sink.use(c);
        c = 11;
        int e = Source.benign();
        Input.send(c);
        Sink.leak(d);
        Sink.sink(e);
    }

    /**
     * Expected output of this method:
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaintImplicitFlow()>
     * Source: line 193: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 209: staticinvoke <sensitive.Sink: void sink(int)>(c)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaintImplicitFlow()>
     * Source: line 194: b = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 210: staticinvoke <sensitive.Sink: void sink(int)>(d)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaintImplicitFlow()>
     * Source: line 194: b = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 211: staticinvoke <sensitive.Sink: void sink(int)>(e#4)
     * ——————————————————
     * Found a Leak in <ProgramToAnalyzeWithExpectedOutputs: void multiTaintImplicitFlow()>
     * Source: line 193: a = staticinvoke <sensitive.Source: int source()>()
     * Leak: line 211: staticinvoke <sensitive.Sink: void sink(int)>(e#4)
     */
    public void multiTaintImplicitFlow() {
        int a = Source.source();
        int b = Source.source();

        int c = 0, d = 0, e = 0;

        if (a > 1) {
            c = 3;
        }

        if (b > 10) {
            d = 5;
        }

        Sink.use(e);
        e = c + d;

        Sink.sink(c);
        Sink.sink(d);
        Sink.sink(e);
    }

}
