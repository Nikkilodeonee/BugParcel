package dev.bugparcel.api;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String,String>> invalid(IllegalArgumentException e) {return ResponseEntity.badRequest().body(Map.of("error",e.getMessage()));}
    @ExceptionHandler({HttpMessageNotReadableException.class,MethodArgumentNotValidException.class})
    public ResponseEntity<Map<String,String>> body(Exception e) {
        for(Throwable cause=e;cause!=null;cause=cause.getCause()) if(cause instanceof RequestSizeLimit.Exceeded)
            return ResponseEntity.status(413).body(Map.of("error","The combined input exceeds 28 MB. Export a shorter recording around the incident."));
        return ResponseEntity.badRequest().body(Map.of("error","The input is malformed or exceeds the supported limits. Use capture/log files up to 10 MB, bounded archives, and custom values of 2–200 characters."));
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String,String>> unexpected(Exception e) {return ResponseEntity.internalServerError().body(Map.of("error","The incident could not be processed. Try a shorter recording or check the supported input formats."));}
}
