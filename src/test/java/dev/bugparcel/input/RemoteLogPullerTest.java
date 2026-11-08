package dev.bugparcel.input;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.*;
import static org.assertj.core.api.Assertions.*;

class RemoteLogPullerTest {
    private final ObjectMapper mapper=new ObjectMapper();
    private HttpServer server;
    private String base;
    @TempDir Path temp;
    @BeforeEach void start()throws Exception {
        // JVM-local workaround for the Windows JDK selector pipe; no system settings change.
        if(System.getProperty("os.name").startsWith("Windows"))System.setProperty("jdk.net.unixdomain.tmpdir",temp.resolve("unused-sockets").toString());
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);server.start();base="http://127.0.0.1:"+server.getAddress().getPort();
    }
    @AfterEach void stop(){if(server!=null)server.stop(0);}
    private void reply(HttpExchange exchange,int status,String text)throws IOException {byte[] bytes=text.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(status,bytes.length);try(var out=exchange.getResponseBody()){out.write(bytes);}}
    private RemoteLogPuller.Options query(RemoteLogPuller.Kind kind,String id,int limit,String auth) {
        return new RemoteLogPuller.Options(kind,base,id,"{app=\"api\"}","logs-*","requestId.keyword",Instant.parse("2026-11-07T14:00:00Z"),Instant.parse("2026-11-07T15:00:00Z"),limit,auth);
    }
    @Test void lokiEscapesLiteralIdsAndPreservesParsedIdsAndZonedTimestamps()throws Exception {
        AtomicReference<String> query=new AtomicReference<>(),authorization=new AtomicReference<>();
        server.createContext("/loki/api/v1/query_range",e->{query.set(URLDecoder.decode(e.getRequestURI().getRawQuery(),StandardCharsets.UTF_8));authorization.set(e.getRequestHeaders().getFirst("Authorization"));reply(e,200,"{\"status\":\"success\",\"data\":{\"resultType\":\"streams\",\"result\":[{\"values\":[[\"1794061928000000000\",\"level=error request_id=pay-42 msg=\\\"Failed\\\"\"]]}]}}");});
        var result=new RemoteLogPuller(mapper).pull(query(RemoteLogPuller.Kind.LOKI,"a\" | drop request_id",100,"Bearer fictional"));
        assertThat(query.get()).contains("{app=\"api\"} |= \"a\\\" | drop request_id\"");assertThat(authorization.get()).isEqualTo("Bearer fictional");
        var parsed=new dev.bugparcel.analysis.LogParser(mapper).parseDetected(result.parts().get(0),new ArrayList<>());
        assertThat(parsed.entries()).hasSize(1);assertThat(parsed.entries().get(0).correlationIds()).containsEntry("requestId","pay-42");
        assertThat(parsed.entries().get(0).timestamp()).endsWith("Z");assertThat(result.limited()).isFalse();
    }
    @Test void elasticsearchUsesATermFilterAndReportsPartialResponses()throws Exception {
        AtomicReference<String> body=new AtomicReference<>();
        server.createContext("/logs-*/_search",e->{body.set(new String(e.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));reply(e,200,"{\"timed_out\":false,\"hits\":{\"total\":{\"value\":3,\"relation\":\"eq\"},\"hits\":[{\"_source\":{\"level\":\"ERROR\",\"requestId\":\"pay-42\",\"message\":\"Failed\"}}]}}");});
        var result=new RemoteLogPuller(mapper).pull(query(RemoteLogPuller.Kind.ELASTICSEARCH,"pay-42\" OR *",1,null));
        var request=mapper.readTree(body.get());assertThat(request.path("query").path("bool").path("filter").get(0).path("term").path("requestId.keyword").path("value").asText()).isEqualTo("pay-42\" OR *");
        assertThat(request.path("size").asInt()).isOne();assertThat(result.limited()).isTrue();assertThat(result.parts().get(0)).contains("pay-42");
        var logInputs=new LogInputs(mapper);var input=logInputs.read(logInputs.bundle(result.parts(),result),"bundle",new ArrayList<>());
        assertThat(input.limited()).isTrue();
    }
    @Test void rawUrlsAndFileUrlsAreBoundedAndNeverFollowRedirects()throws Exception {
        AtomicInteger target=new AtomicInteger();
        server.createContext("/logs",e->reply(e,200,"{\"message\":\"direct\"}"));
        server.createContext("/target",e->{target.incrementAndGet();reply(e,200,"should not reach");});
        server.createContext("/redirect",e->{e.getResponseHeaders().add("Location",base+"/target");reply(e,302,"private-service-error");});
        var url=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,base+"/logs",null,null,null,null,null,null,10,null);
        assertThat(new RemoteLogPuller(mapper).pull(url).parts()).containsExactly("{\"message\":\"direct\"}");
        var redirect=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,base+"/redirect",null,null,null,null,null,null,10,null);
        assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(redirect)).hasMessageContaining("HTTP 302").hasMessageNotContaining("private-service-error");assertThat(target).hasValue(0);
        Path file=temp.resolve("local.log");Files.writeString(file,"local evidence");
        var local=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,file.toUri().toString(),null,null,null,null,null,null,10,null);
        assertThat(new RemoteLogPuller(mapper).pull(local).parts()).containsExactly("local evidence");
    }
    @Test void unsafeUrlsMissingIdsAndBroadRangesFailBeforeAnyFetch() {
        for(String source:List.of("http://user:password@127.0.0.1/logs","file://remote-host/share/logs","ftp://example.test/logs","relative-path")) {
            var options=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,source,null,null,null,null,null,null,1,null);
            assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(options)).isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("password");
        }
        assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(query(RemoteLogPuller.Kind.LOKI,null,100,null))).hasMessageContaining("request ID");
        assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(query(RemoteLogPuller.Kind.LOKI,"id",10001,null))).hasMessageContaining("limit");
        var unsafeAuth=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,"http://example.test/logs",null,null,null,null,null,null,1,"Bearer fictional");
        assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(unsafeAuth)).hasMessageContaining("HTTPS");
    }
    @Test void malformedServiceResponsesAndErrorBodiesDoNotEchoCapturedSecrets() {
        server.createContext("/logs-*/_search",e->reply(e,500,"fictional-private-token"));
        assertThatThrownBy(()->new RemoteLogPuller(mapper).pull(query(RemoteLogPuller.Kind.ELASTICSEARCH,"id",1,null))).hasMessageContaining("HTTP 500").hasMessageNotContaining("fictional-private-token");
    }
    @Test void subscriberCancelsBeforeBufferingBeyondItsBudget() {
        var body=new RemoteLogPuller.LimitedBody(4);var canceled=new AtomicBoolean();
        body.onSubscribe(new Flow.Subscription(){public void request(long n){}public void cancel(){canceled.set(true);}});
        body.onNext(List.of(ByteBuffer.wrap(new byte[5])));
        assertThat(canceled).isTrue();assertThat(body.getBody().toCompletableFuture()).isCompletedExceptionally();
    }
    @Test void deadlineIncludesTheBodyAfterHeadersArrive() {
        server.createContext("/slow",e->{e.sendResponseHeaders(200,0);try(var out=e.getResponseBody()){out.write('x');out.flush();try{Thread.sleep(500);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}});
        var options=new RemoteLogPuller.Options(RemoteLogPuller.Kind.URL,base+"/slow",null,null,null,null,null,null,1,null);
        assertThatThrownBy(()->new RemoteLogPuller(mapper,Duration.ofMillis(150)).pull(options)).hasMessageContaining("timed out");
    }
}
