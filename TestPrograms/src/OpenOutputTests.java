import sensitive.Sink;
import sensitive.Source;

public class OpenOutputTests {
    public void array() {
        int[] array = new int[5];

        array[0] = Source.source();
        array[1] = 5;

        Sink.sink(array[1]);
    }

    public void deadcode() {
        int a = Source.source();
        int b = 9;
        if (b > 10) {
            Sink.leak(a);
        }
    }

    public void objectExample() {
        Example example = new Example();
        example.setA(Source.source());
        Sink.sink(example.getA());
        Sink.sink(example.getB());

        example.b = Source.source();
        Sink.sink(example.getB());
    }
}

class Example {
    public int a = 1;
    public int b = 1;

    public int getA() {
        return a;
    }

    public void setA(int a) {
        this.a = a;
    }

    public int getB() {
        return b;
    }

    public void setB(int b) {
        this.b = b;
    }
}