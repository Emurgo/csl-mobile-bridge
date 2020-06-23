package io.emurgo.rnhaskellshelley;

import com.facebook.react.bridge.Promise;

interface Function<T,R> {
    R apply(T t);
}

final class Result<T> {
    private final T value;
    private final String error;

    static <T> Result<T> ok(T value) { return new Result<>(value, null); }
    static <T> Result<T> err(String error) { return new Result<>(null, error); }

    final <T2> Result<T2> map(Function<T, T2> mapper) {
        if (this.value != null) {
            try {
                return ok(mapper.apply(this.value));
            } catch (Throwable throwable) {
                return err(throwable.toString());
            }
        }
        return new Result<T2>(null, this.error);
    }

    final boolean isOk() {
        return this.error == null;
    }

    final boolean isErr() {
        return this.error != null;
    }

    final Result mapErr(Function<String, String> mapper) {
        return this.error != null ? err(mapper.apply(this.error)) : this;
    }

    final void pour(Promise promise) {
        if (this.error != null) {
            promise.reject("0", this.error);
        } else {
            promise.resolve(this.value);
        }
    }

    Result(T value, String error) {
        this.value = value;
        this.error = error;
    }
}
