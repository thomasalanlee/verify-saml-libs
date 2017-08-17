package uk.gov.ida.saml.transformers;

/**
 *
 * @param <TInput> the type of the input to the function
 * @param <TOutput> the type of the result of the function
 * @deprecated Use java 8's {@link java.util.function.Function Function} interface instead
 *
 */
@Deprecated
public interface Transformer<TInput, TOutput> {
	
	/**
	 * @deprecated Use {@link java.util.function.Function#apply apply} instead
	 */
	@Deprecated
    TOutput transform(TInput input);
}
