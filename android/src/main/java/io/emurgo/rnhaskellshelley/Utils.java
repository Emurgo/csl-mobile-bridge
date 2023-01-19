package io.emurgo.rnhaskellshelley;

public final class Utils {
    public static Double boxedLongToDouble(Long value) {
        return value == null ? null : value.doubleValue();
    }
}
