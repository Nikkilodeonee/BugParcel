package dev.bugparcel.input;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.analysis.*;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import static org.assertj.core.api.Assertions.*;

class InputTierFourTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final IncidentService service = new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
    @TempDir Path temp;
    private byte[] sample(String name) throws IOException { try(var in=getClass().getResourceAsStream("/samples/"+name)){return Objects.requireNonNull(in).readAllBytes();} }
    private Analysis analyze(byte[] capture,byte[] logs,boolean bodies) {
        return service.analyze(new AnalysisInput(Base64.getEncoder().encodeToString(capture),logs==null?null:Base64.getEncoder().encodeToString(logs),"Input test",null,List.of(),bodies,Set.of(),Set.of(),false,null,null,null,null,"base64",logs==null?null:"base64"));
    }
    private static byte[] gzip(byte[] bytes)throws IOException {var out=new ByteArrayOutputStream();try(var zip=new GZIPOutputStream(out)){zip.write(bytes);}return out.toByteArray();}
    private static byte[] zip(Map<String,byte[]> files)throws IOException {var out=new ByteArrayOutputStream();try(var zip=new ZipOutputStream(out)){for(var f:files.entrySet()){zip.putNextEntry(new ZipEntry(f.getKey()));zip.write(f.getValue());zip.closeEntry();}}return out.toByteArray();}

    @ParameterizedTest @CsvSource({"checkout.har,HAR,5","charles-checkout.xml,Charles XML,5","mitmproxy-checkout.mitm,mitmproxy flows,5","newman-checkout.json,Postman / Newman run,5","postman-checkout.json,Postman run summary,0","playwright-checkout.zip,Playwright trace,5"})
    void supportedCapturesUseTheSameCorrelationAndRedactionBoundary(String file,String format,int linked)throws Exception {
        var result=analyze(sample(file),sample("checkout-logs.zip"),true);
        assertThat(result.incident().sources().captureFormat()).isEqualTo(format);
        assertThat(result.incident().sources().logFiles()).isEqualTo(2);
        assertThat(result.incident().requests()).hasSize(6);assertThat(result.incident().logs()).hasSize(9);
        assertThat(result.failedRequests()).isEqualTo(2);assertThat(result.matchedRequests()).isEqualTo(linked);
        for(String output:List.of(mapper.writeValueAsString(result.incident()),new ReportExporter().html(result.incident()),new ReportExporter().markdown(result.incident())))assertThat(output).doesNotContain("alex.morgan@example.test","dev-only-token-not-a-real-secret","demo-session-value","10.24.8.16");
        assertThat(result.incident().security().selfCheck().remainingValues()).isZero();
    }
    @Test void newmanAndSummaryImportsDoNotInventAbsoluteTimesOrTreatAssertionsAsHttpFailures()throws Exception {
        var json=mapper.readTree(sample("newman-checkout.json"));
        ((com.fasterxml.jackson.databind.node.ObjectNode)json.path("run").path("executions").get(0)).putArray("assertions").addObject().putObject("error").put("message","test failed");
        var result=analyze(json.toString().getBytes(StandardCharsets.UTF_8),null,true);
        assertThat(result.failedRequests()).isEqualTo(2);
        assertThat(result.incident().report().untimedRequests()).isEqualTo(6);
        assertThat(result.incident().requests().get(0).status()).isEqualTo(200);
        assertThat(result.incident().requests().get(1).requestBody()).contains("REDACTED_EMAIL");
    }
    @Test void charlesExternalDtdIsIgnoredButInternalEntitiesAreRejectedWithoutEchoingThem()throws Exception {
        assertThat(analyze(sample("charles-checkout.xml"),null,true).incident().requests()).hasSize(6);
        String attack="<!DOCTYPE charles-session [<!ENTITY private SYSTEM 'file:///private-sensitive-name'>]><charles-session>&private;</charles-session>";
        assertThatThrownBy(()->analyze(attack.getBytes(StandardCharsets.UTF_8),null,true)).isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("private-sensitive-name");
    }
    @Test void playwrightAttachedBodiesAreReadOnlyFromArchiveAndRespectBodyInclusion()throws Exception {
        var root=mapper.readTree(sample("checkout.har"));
        var body=(com.fasterxml.jackson.databind.node.ObjectNode)root.path("log").path("entries").get(0).path("response").path("content");
        body.remove("text");body.put("_file","payload.json");
        var bytes=zip(Map.of("record.har",root.toString().getBytes(StandardCharsets.UTF_8),"payload.json","{\"email\":\"body@example.test\"}".getBytes(StandardCharsets.UTF_8)));
        assertThat(analyze(bytes,null,true).incident().requests().get(0).responseBody()).contains("REDACTED_EMAIL").doesNotContain("body@example.test");
        assertThat(analyze(bytes,null,false).incident().requests().get(0).responseBody()).isEmpty();
        var missing=analyze(root.toString().getBytes(StandardCharsets.UTF_8),null,true);
        assertThat(missing.incident().warnings()).anyMatch(n->n.contains("referenced capture body is missing"));
        body.put("_file","https://private.example.test/body");
        assertThatThrownBy(()->analyze(root.toString().getBytes(StandardCharsets.UTF_8),null,true)).isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("private.example.test");
    }
    @Test void gzipCapturesAndUtf16LogsAreAccepted()throws Exception {
        byte[] text="{\"message\":\"person@example.test\"}".getBytes(StandardCharsets.UTF_16LE), utf16=new byte[text.length+2];utf16[0]=(byte)255;utf16[1]=(byte)254;System.arraycopy(text,0,utf16,2,text.length);
        var result=analyze(gzip(sample("checkout.har")),gzip(utf16),true);
        assertThat(result.incident().logs()).hasSize(1);assertThat(result.incident().logs().get(0).message()).contains("REDACTED_EMAIL");
    }
    @Test void archiveNamesDuplicatesAndAmbiguousCapturesAreRejected()throws Exception {
        for(String path:List.of("../secret.log","/secret.log","C:/secret.log","a/../../secret.log","a\\..\\secret.log"))assertThatThrownBy(()->InputBytes.unzip(zip(Map.of(path,new byte[]{1})))).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Unsafe");
        assertThatThrownBy(()->analyze(zip(Map.of("a.har",sample("checkout.har"),"b.har",sample("checkout.har"))),null,false)).hasMessageContaining("one capture");
        assertThatThrownBy(()->new LogInputs(mapper).files(zip(Map.of("inner.log",zip(Map.of("a.log",new byte[]{1})))),new ArrayList<>())).hasMessageContaining("Nested");
        assertThatThrownBy(()->new LogInputs(mapper).files(zip(Map.of("inner.zip",zip(Map.of("a.log",new byte[]{1})),"visible.log","one".getBytes(StandardCharsets.UTF_8))),new ArrayList<>())).hasMessageContaining("Nested");
    }
    @Test void expansionLimitsAndCorruptDataFailAtomically()throws Exception {
        byte[] bomb=gzip(new byte[InputBytes.MAX_TEXT+1]);
        assertThatThrownBy(()->new LogInputs(mapper).files(bomb,new ArrayList<>())).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("limit");
        byte[] valid=gzip("hello".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(()->InputBytes.gunzip(Arrays.copyOf(valid,valid.length-2),InputBytes.MAX_TEXT)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("corrupt");
        assertThatThrownBy(()->InputBytes.text(new byte[]{(byte)0xff,0,5})).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->InputBytes.transport("private-input","invalid")).isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining("private-input");
    }
    @Test void jsonArraysMixWithPlainLogsAndBracketPrefixedTextIsRetained() {
        var result=new LogInputs(mapper).merge(List.of("[{\"message\":\"one\"},{\"message\":\"two\"}]","[worker] custom text"));
        assertThat(result.files()).isEqualTo(2);assertThat(result.text()).contains("[worker] custom text","\"one\"","\"two\"");
    }
    @Test void directoryAndQuotedGlobInputsAreDeterministicDeduplicatedAndBounded()throws Exception {
        Files.createDirectories(temp.resolve("logs/nested"));
        Files.writeString(temp.resolve("logs/a.log"),"first");Files.writeString(temp.resolve("logs/nested/b.log"),"second");Files.writeString(temp.resolve("logs/ignored.md"),"ignore");
        var files=new LogFileInputs(temp,mapper);
        var selected=files.resolve(List.of("logs/**/*.log","logs/a.log"));
        assertThat(selected).hasSize(2);assertThat(files.read(selected)).containsExactly("first","second");
        assertThat(files.resolve(List.of("logs"))).hasSize(2);
        assertThat(files.resolve(List.of("**/logs/**/*.log"))).hasSize(2);
        assertThatThrownBy(()->files.resolve(List.of("logs/*.missing"))).hasMessageContaining("matched no");
    }
    @Test void malformedNativeFlowsAndUnrecognizedCollectionsAreActionable()throws Exception {
        assertThatThrownBy(()->analyze("99999999:private,".getBytes(StandardCharsets.UTF_8),null,false)).hasMessageContaining("typed-netstring").hasMessageNotContaining("private");
        assertThatThrownBy(()->analyze("{\"info\":{},\"item\":[]}".getBytes(StandardCharsets.UTF_8),null,false)).hasMessageContaining("Unsupported capture");
        assertThatThrownBy(()->analyze(zip(Map.of("trace.network","{\"type\":\"unknown\"}".getBytes(StandardCharsets.UTF_8))),null,false)).hasMessageContaining("no supported network snapshots");
    }
    @Test void rotatedLogsAreDiscoveredInDirectoriesAndArchives()throws Exception {
        Files.createDirectories(temp.resolve("rotated"));
        Files.writeString(temp.resolve("rotated/app.log.1"),"numbered");
        Files.writeString(temp.resolve("rotated/app.log.2026-11-07"),"dated");
        Files.write(temp.resolve("rotated/app.log.2.gz"),gzip("compressed".getBytes(StandardCharsets.UTF_8)));
        Files.writeString(temp.resolve("rotated/app.log.backup"),"ignore");
        var reader=new LogFileInputs(temp,mapper);
        var files=reader.resolve(List.of("rotated"));
        assertThat(files).hasSize(3);assertThat(reader.read(files)).containsExactlyInAnyOrder("numbered","dated","compressed");
        var archived=new LogInputs(mapper).files(zip(Map.of("logs/app.log.1","one".getBytes(StandardCharsets.UTF_8),"logs/app.log.2026-11-07","two".getBytes(StandardCharsets.UTF_8))),new ArrayList<>());
        assertThat(archived).containsExactlyInAnyOrder("one","two");
        assertThat(reader.resolve(List.of("rotated/*.log.*"))).hasSize(3);
    }
    @Test void aDigitPrefixStillRequiresAValidNetstringRecord() {
        byte[] invalid="2026-11-07 private-not-a-flow".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(()->analyze(invalid,null,false)).isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("typed-netstring").hasMessageNotContaining("private-not-a-flow");
    }
    @Test void encodedSourcesSurviveComparisonReanalysis()throws Exception {
        String source=Base64.getEncoder().encodeToString(sample("playwright-checkout.zip"));
        var input=new AnalysisInput(source,null,"Trace",null,List.of(),true,Set.of(),Set.of(),false,null,null,null,"paper","base64",null);
        var result=new IncidentComparison(service,mapper).compare(new ComparisonInput(input,input,true));
        assertThat(result.summary().unchanged()).isEqualTo(6);assertThat(result.before().sources().captureFormat()).isEqualTo("Playwright trace");
    }
    @Test void repeatedReferencesCannotMultiplyOneBodyPastTheMemoryBudget()throws Exception {
        var root=mapper.readTree(sample("checkout.har"));
        for(var entry:root.path("log").path("entries")) {
            var body=(com.fasterxml.jackson.databind.node.ObjectNode)entry.path("response").path("content");body.remove("text");body.put("_file","shared.txt");
        }
        byte[] payload=new byte[2_100_000];Arrays.fill(payload,(byte)'a');
        byte[] archive=zip(Map.of("one.har",root.toString().getBytes(StandardCharsets.UTF_8),"shared.txt",payload));
        assertThatThrownBy(()->analyze(archive,null,true)).hasMessageContaining("materialization budget");
    }
    @Test void playwrightMissingResponseStatusCountsAsANetworkFailure()throws Exception {
        var root=mapper.readTree(sample("checkout.har"));
        var entry=(com.fasterxml.jackson.databind.node.ObjectNode)root.path("log").path("entries").get(0);entry.put("time",-1);((com.fasterxml.jackson.databind.node.ObjectNode)entry.path("response")).put("status",-1);
        var result=analyze(root.toString().getBytes(StandardCharsets.UTF_8),null,false);
        assertThat(result.failedRequests()).isEqualTo(3);assertThat(result.incident().requests().get(0).status()).isZero();
        assertThat(result.incident().warnings()).anyMatch(n->n.contains("completion time is approximate"));
    }
    @Test void deepXmlAndPartialPullsHaveExplicitLimits()throws Exception {
        String xml="<charles-session>"+"<nested>".repeat(40)+"</nested>".repeat(40)+"</charles-session>";
        assertThatThrownBy(()->analyze(xml.getBytes(StandardCharsets.UTF_8),null,false)).isInstanceOf(IllegalArgumentException.class);
        var pull=new RemoteLogPuller.Result(List.of("{\"message\":\"partial\"}"),"Loki",true);
        String logs=new LogInputs(mapper).bundle(pull.parts(),pull);
        var result=service.analyze(new AnalysisInput(new String(sample("checkout.har"),StandardCharsets.UTF_8),logs,"Partial",null,List.of(),false,Set.of(),Set.of(),false,null,null,null,null,null,"bundle"));
        assertThat(result.incident().security().scanLimited()).isTrue();assertThat(result.incident().warnings()).anyMatch(n->n.contains("partial response"));
    }
}
