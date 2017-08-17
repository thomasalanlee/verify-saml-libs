package uk.gov.ida.saml.transformers;

import org.junit.Test;

import java.util.function.Function;
import static org.assertj.core.api.Assertions.assertThat;

public class CompositeTransformerTest {

    @Test
    public void shouldComposeTransformers() throws Exception {
        Transformer<A, B> firstTransformer = new TransformerAB();
        Transformer<B, C> secondTransformer = new TransformerBC();
        CompositeTransformer compositeTransformer = new CompositeTransformer(firstTransformer, secondTransformer);

        Object actualResult = compositeTransformer.transform(new A());

        assertThat(actualResult).isEqualTo(new C());
    }

    @Test
    public void replaceWithRealFunctionalComposition(){
        Transformer<A, B> firstTransformer = new TransformerAB();
        Transformer<B, C> secondTransformer = new TransformerBC();
        Transformer<A, C> compositeTransformer = CompositeTransformer.compose(firstTransformer, secondTransformer);

        Object actualResult = compositeTransformer.transform(new A());

        assertThat(actualResult).isEqualTo(new C());
    }

    @Test
    public void shouldComposeTransformersWithJava8() throws Exception {
        Function<A, B> firstTransformer = new FunctionAB();
        Function<B, C> secondTransformer = new FunctionBC();
        Function<A, C> compositeTransformer = secondTransformer.compose(firstTransformer);

        C expectedResult = new C();

        Object actualResult = compositeTransformer.apply(new A());

        assertThat(actualResult).isEqualTo(expectedResult);
    }

    private class A {
    }

    private class B {
    }

    private class C {
        @Override
        public boolean equals(Object obj) {
            return obj instanceof C;
        }
    }

    private class TransformerAB implements Transformer<A, B> {
        @Override
        public B transform(A a) {
            return new B();
        }
    }

    private class TransformerBC implements Transformer<B, C> {
        @Override
        public C transform(B b) {
            return new C();
        }
    }

    private class FunctionAB implements Function<A, B> {
        @Override
        public B apply(A a) {
            return new B();
        }
    }

    private class FunctionBC implements Function<B, C> {
        @Override
        public C apply(B b) {
            return new C();
        }
    }
}
