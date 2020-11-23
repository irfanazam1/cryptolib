package cryptolib.core;
public enum BlockMode {
    CBC("CBC"),
    ECB("ECB"),
    CTR("CTR"),
    GCM("GCM");
    private final String value;
    BlockMode(String value){
        this.value = value;
    }
    public static BlockMode fromValue(String value){
        if(value != null && value.length() > 0) {
            for (BlockMode typ : values()) {
                if (typ.value.equalsIgnoreCase(value)) {
                    return typ;
                }
            }
        }
        throw new IllegalArgumentException("BlockMode");
    }
}
