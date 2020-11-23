package cryptolib.core;
public enum Algorithm {
    AES("AES"),
    RSA("RSA"),
    EC("EC"),
    HMAC("HMAC"),
    DES("DESede"),
    ALGORITHM_UNRECOGNIZED("UNRECOGNIZED");
    private final String value;
    Algorithm(String value){
        this.value = value;
    }
    public static Algorithm fromValue(String value){
        if(value != null && value.length() > 0) {
            for (Algorithm typ : values()) {
                if (typ.value.equalsIgnoreCase(value)) {
                    return typ;
                }
            }
        }
        throw new IllegalArgumentException("Algorithm");
    }
}
