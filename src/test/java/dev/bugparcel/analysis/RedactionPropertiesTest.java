package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import net.jqwik.api.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

/** Generated synthetic values only. Seeds and shrinking make failing cases reproducible. */
class RedactionPropertiesTest {
    final ObjectMapper mapper=new ObjectMapper();
    final IncidentService service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);

    @Provide Arbitrary<String> tokenSuffixes() {
        return Arbitraries.strings().withCharRange('a','z').withCharRange('A','Z').withCharRange('0','9').ofLength(36);
    }
    @Provide Arbitrary<String> surroundings() {
        return Arbitraries.strings().withChars(' ', '\n', '\t', '<', '>', '&', '\'', '"', '`', '\\', '/', ':', ';', 'ę', 'ż').ofMaxLength(30);
    }

    @Property(tries=200, seed="2026110701")
    void providerSecretsNeverSurviveSupportedDirectOrEncodedExports(@ForAll("tokenSuffixes") String suffix,
                                                                    @ForAll("surroundings") String surrounding) throws Exception {
        String secret="ghp_"+suffix;
        String encoded=Base64.getEncoder().encodeToString(("{\"apiKey\":\""+secret+"\"}").getBytes(StandardCharsets.UTF_8));
        var root=mapper.createObjectNode();var entry=root.putObject("log").putArray("entries").addObject();
        entry.put("startedDateTime","2026-11-07T14:32:08Z").put("time",10);
        var req=entry.putObject("request").put("method","POST").put("url","https://example.test/?payload="+URLEncoder.encode(encoded,StandardCharsets.UTF_8));
        req.putArray("headers").addObject().put("name","X-API-Key").put("value",secret);
        req.putObject("postData").put("mimeType","application/json").put("text",mapper.createObjectNode().put("password",secret).put("encoded",encoded).toString());
        entry.putObject("response").put("status",500).putArray("headers");
        String logs=mapper.createObjectNode().put("message",surrounding+" "+secret+" payload="+encoded+" "+surrounding).toString();
        var incident=service.analyze(new AnalysisInput(root.toString(),logs,"Synthetic",null,List.of(),true)).incident();
        var exporter=new ReportExporter();
        for(String report:List.of(mapper.writeValueAsString(incident),exporter.html(incident),exporter.markdown(incident)))
            assertThat(report).doesNotContain(secret,encoded);
        assertThat(incident.security().selfCheck().remainingValues()).isZero();
        assertThat(incident.security().selfCheck().completed()).isTrue();
    }

    @Property(tries=150, seed="2026110702")
    void exactCustomValuesAreRemovedInsideIdsAndKeepCorrelationIntact(@ForAll("tokenSuffixes") String suffix,
                                                                     @ForAll("surroundings") String surrounding) throws Exception {
        String secret="customer-"+suffix;
        var root=mapper.createObjectNode();var entry=root.putObject("log").putArray("entries").addObject();
        entry.put("startedDateTime","2026-11-07T14:32:08Z").put("time",10);
        var req=entry.putObject("request").put("method","GET").put("url","https://example.test/");
        req.putArray("headers").addObject().put("name","X-Request-ID").put("value","prefix_"+secret+"_suffix");
        entry.putObject("response").put("status",200).putArray("headers");
        String logs=mapper.createObjectNode().put("requestId","prefix_"+secret+"_suffix").put("message",surrounding+secret+surrounding).toString();
        var result=service.analyze(new AnalysisInput(root.toString(),logs,"Synthetic",null,List.of(secret),false));
        assertThat(result.matchedRequests()).isOne();
        var exporter=new ReportExporter();
        for(String report:List.of(mapper.writeValueAsString(result.incident()),exporter.html(result.incident()),exporter.markdown(result.incident())))
            assertThat(report).doesNotContain(secret);
        assertThat(result.incident().requests().get(0).logIds()).containsExactly("log-1");
    }
}
