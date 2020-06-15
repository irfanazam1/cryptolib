package core;

public enum Purpose {
    ENCRYPT("ENCRYPT"),
    DECRYPT("DECRYPT"),
    SIGN("SIGN"),
    VERIFY("VERIFY");
    private final String value;
    Purpose(String value){
        this.value = value;
    }
    public static Purpose fromValue(String value) throws IllegalArgumentException{
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
