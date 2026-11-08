package dev.bugparcel.api;

import dev.bugparcel.analysis.IncidentService;
import dev.bugparcel.analysis.IncidentComparison;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.export.ComparisonExporter;
import dev.bugparcel.export.RequestSnippets;
import dev.bugparcel.model.Models.*;
import jakarta.validation.Valid;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class IncidentController {
    private final IncidentService service; private final ReportExporter exporter; private final IncidentComparison comparison;
    public IncidentController(IncidentService service,ReportExporter exporter,IncidentComparison comparison) {this.service=service;this.exporter=exporter;this.comparison=comparison;}
    @GetMapping("/health") public Map<String,String> health() {return Map.of("status","ok","version","1.3.0");}
    @GetMapping("/sample") public Map<String,String> sample() throws IOException {
        return Map.of("har",read("checkout.har"),"logs",read("checkout.ndjson"),"title","Checkout fails after payment confirmation");
    }
    @GetMapping("/sample/security") public Map<String,String> securitySample() throws IOException {
        return Map.of("har",read("security.har"),"logs",read("security.ndjson"),"title","Synthetic redaction stress test",
            "policyYaml",read("bugparcel.example.yml"));
    }
    @GetMapping("/sample/fixed") public Map<String,String> fixedSample() throws IOException {
        return Map.of("har",read("checkout-fixed.har"),"logs",read("checkout-fixed.ndjson"),"title","Checkout after database pool fix (synthetic)");
    }
    @PostMapping("/analyze") public Analysis analyze(@Valid @RequestBody AnalysisInput input) {return service.analyze(input);}
    @PostMapping(value="/request/{id}/snippet/{format}",produces=MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> snippet(@PathVariable String id,@PathVariable String format,@Valid @RequestBody AnalysisInput input) {
        return download(new RequestSnippets().render(service.analyze(input).incident(),id,format),"text/plain;charset=UTF-8","bugparcel-"+id+"."+(format.equals("curl")||format.equals("httpie")?"sh":"txt"));
    }
    @PostMapping("/compare") public Comparison compare(@Valid @RequestBody ComparisonInput input){return comparison.compare(input);}
    @PostMapping("/compare/requests") public Comparison compareRequests(@Valid @RequestBody RequestComparisonInput input){return comparison.requests(input);}
    @PostMapping("/compare/export/{format}") public ResponseEntity<String> compareExport(@PathVariable String format,@Valid @RequestBody ComparisonInput input)throws IOException{return comparisonDownload(comparison.compare(input),format);}
    @PostMapping("/compare/requests/export/{format}") public ResponseEntity<String> requestCompareExport(@PathVariable String format,@Valid @RequestBody RequestComparisonInput input)throws IOException{return comparisonDownload(comparison.requests(input),format);}
    private ResponseEntity<String> comparisonDownload(Comparison result,String format)throws IOException {
        var reports=new ComparisonExporter();
        return switch(format){
            case "html"->download(reports.html(result),"text/html;charset=UTF-8","bugparcel-comparison.html");
            case "markdown"->download(reports.markdown(result),"text/plain;charset=UTF-8","bugparcel-comparison.md");
            case "json"->download(new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result),"application/json;charset=UTF-8","bugparcel-comparison.json");
            default->throw new IllegalArgumentException("Comparison format must be html, markdown, or json.");
        };
    }
    @PostMapping(value="/export/html",produces=MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> html(@Valid @RequestBody AnalysisInput input) {return download(exporter.html(service.analyze(input).incident()),"text/html;charset=UTF-8","bugparcel-report.html");}
    @PostMapping(value="/export/markdown",produces=MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> markdown(@Valid @RequestBody AnalysisInput input) {return download(exporter.markdown(service.analyze(input).incident()),"text/plain;charset=UTF-8","bugparcel-report.md");}
    @PostMapping(value="/export/json",produces=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Incident> json(@Valid @RequestBody AnalysisInput input) {return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\"bugparcel-report.json\"").body(service.analyze(input).incident());}
    private ResponseEntity<String> download(String body,String type,String name) {return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE,type).header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+name+"\"").body(body);}
    private String read(String name)throws IOException {return new ClassPathResource("samples/"+name).getContentAsString(StandardCharsets.UTF_8);}
}
