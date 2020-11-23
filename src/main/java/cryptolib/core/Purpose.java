package cryptolib.core;

public enum Purpose {
    ENCRYPT("ENCRYPT"),
    DECRYPT("DECRYPT"),
    SIGN("SIGN"),
    VERIFY("VERIFY"),
    PURPOSE_UNRECOGNIZED("UNRECOGNIZED");
    private final String value;
    Purpose(String value){
        this.value = value;
    }
    public static Purpose fromValue(String value){
        if(value != null && value.length() > 0) {
            for (Purpose typ : values()) {
                if (typ.value.equalsIgnoreCase(value)) {
                    return typ;
                }
            }
        }
        throw new IllegalArgumentException("Purpose");
    }
}
