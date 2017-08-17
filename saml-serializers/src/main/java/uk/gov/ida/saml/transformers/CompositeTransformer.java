package uk.gov.ida.saml.transformers;


import java.util.function.Function;

/**
 *
 * @deprecated Use java 8's {@link java.util.function.Function#compose(Function)} Function} instead
 * e.g. secondTransformer.compose(firstTransformer)
 *
 */
@Deprecated
public class CompositeTransformer<TInput, TIntermediary, TOutput> implements Transformer<TInput, TOutput> {
    private final Transformer<TInput, TIntermediary> inputTIntermediaryTransformer;
    private final Transformer<TIntermediary, TOutput> intermediaryTOutputTransformer;

    /**
     * @deprecated Use java 8's {@link java.util.function.Function#compose(Function) compose} instead, e.g. secondTransformer.compose(firstTransformer)
     */
    public CompositeTransformer(Transformer<TInput, TIntermediary> inputTIntermediaryTransformer, Transformer<TIntermediary, TOutput> intermediaryTOutputTransformer) {
        this.inputTIntermediaryTransformer = inputTIntermediaryTransformer;
        this.intermediaryTOutputTransformer = intermediaryTOutputTransformer;
    }

    public TOutput transform(TInput input) {
        return intermediaryTOutputTransformer.transform(inputTIntermediaryTransformer.transform(input));
    }

    /**
     * @deprecated Use java 8's {@link java.util.function.Function#compose(Function) compose} instead, e.g. secondTransformer.compose(firstTransformer)
     */
    public static <T1,T2,T3> Transformer<T1,T3> compose(Transformer<T1,T2> a, Transformer<T2,T3> b) {
        return new CompositeTransformer<>(a, b);
    }

}
