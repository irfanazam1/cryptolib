package core;

public enum PaddingMode {
    NO_PADDING("NoPadding"),
    PKCS7_PADDING("PKCS7Padding"),
    PSS_PADDING("PSS"),
    PKCS1_ENCRYPT_PADDING("PKCS1Padding"),
    PKCS1_SIGN_PADDING("PKCS1"),
    OAEP_PADDING("OAEPPadding");
    private String value;
    PaddingMode(String value){
        this.value = value;
    }

    public static PaddingMode fromValue(String value) throws IllegalArgumentException{
        if(value != null && value.length() > 0) {
            for (PaddingMode typ : values()) {
                if (typ.value.equalsIgnoreCase(value)) {
                    return typ;
                }
            }
        }
        throw new IllegalArgumentException("PaddingMode");
    }

    public String value(){
        return value;
    }
}
