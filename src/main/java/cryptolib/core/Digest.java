package cryptolib.core;
public enum Digest {
    DIGEST_NONE("DIGEST_NONE"),
    MD5("DIGEST_MD5"),
    SHA1("DIGEST_SHA1"),
    SHA_2_224("DIGEST_SHA_2_224"),
    SHA_2_256("DIGEST_SHA_2_256"),
    SHA_2_384("DIGEST_SHA_2_384"),
    SHA_2_512("DIGEST_SHA_2_512"),
    DIGEST_UNRECOGNIZED("UNRECOGNIZED");
    private final String value;
    Digest(String value){
        this.value = value;
    }
    public static Digest fromValue(String value){
        if(value != null && value.length() > 0) {
            for (Digest typ : values()) {
                if (typ.value.equalsIgnoreCase(value)) {
                    return typ;
                }
            }
        }
        throw new IllegalArgumentException("Digest");
    }
}
