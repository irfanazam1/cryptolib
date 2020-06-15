package core;

public class CryptoLibRuntimeException extends RuntimeException{

    public CryptoLibRuntimeException(Throwable e){
        super(e);
    }

    public CryptoLibRuntimeException(String message){
        super(message);
    }
}
