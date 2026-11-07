package dev.bugparcel.api;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;

/** Bounds chunked requests as well as requests that declare Content-Length. */
final class RequestSizeLimit extends HttpServletRequestWrapper {
    static final long MAX_BYTES=28_000_000;
    static final class Exceeded extends IOException { Exceeded(){super("Request size limit exceeded");} }
    private ServletInputStream bounded;
    RequestSizeLimit(HttpServletRequest request){super(request);}
    @Override public ServletInputStream getInputStream()throws IOException {
        if(bounded!=null)return bounded;
        ServletInputStream delegate=super.getInputStream();
        bounded=new ServletInputStream(){
            private long count;
            private void consumed(int bytes)throws IOException {if(bytes>0 && (count+=bytes)>MAX_BYTES)throw new Exceeded();}
            @Override public int read()throws IOException {int value=delegate.read();if(value>=0)consumed(1);return value;}
            @Override public int read(byte[] buffer,int offset,int length)throws IOException {int bytes=delegate.read(buffer,offset,length);consumed(bytes);return bytes;}
            @Override public boolean isFinished(){return delegate.isFinished();}
            @Override public boolean isReady(){return delegate.isReady();}
            @Override public void setReadListener(ReadListener listener){delegate.setReadListener(listener);}
            @Override public void close()throws IOException{delegate.close();}
        };
        return bounded;
    }
}
