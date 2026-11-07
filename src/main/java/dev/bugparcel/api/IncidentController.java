package dev.bugparcel.api;

import dev.bugparcel.analysis.IncidentService;
import dev.bugparcel.export.ReportExporter;
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
    private final IncidentService service; private final ReportExporter exporter;
    public IncidentController(IncidentService service,ReportExporter exporter) {this.service=service;this.exporter=exporter;}
    @GetMapping("/health") public Map<String,String> health() {return Map.of("status","ok","version","1.2.0");}
    @GetMapping("/sample") public Map<String,String> sample() throws IOException {
        return Map.of("har",read("checkout.har"),"logs",read("checkout.ndjson"),"title","Checkout fails after payment confirmation");
    }
    @GetMapping("/sample/security") public Map<String,String> securitySample() throws IOException {
        return Map.of("har",read("security.har"),"logs",read("security.ndjson"),"title","Synthetic redaction stress test",
            "policyYaml",read("bugparcel.example.yml"));
    }
    @PostMapping("/analyze") public Analysis analyze(@Valid @RequestBody AnalysisInput input) {return service.analyze(input);}
    @PostMapping(value="/export/html",produces=MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> html(@Valid @RequestBody AnalysisInput input) {return download(exporter.html(service.analyze(input).incident()),"text/html;charset=UTF-8","bugparcel-report.html");}
    @PostMapping(value="/export/markdown",produces=MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> markdown(@Valid @RequestBody AnalysisInput input) {return download(exporter.markdown(service.analyze(input).incident()),"text/plain;charset=UTF-8","bugparcel-report.md");}
    @PostMapping(value="/export/json",produces=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Incident> json(@Valid @RequestBody AnalysisInput input) {return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\"bugparcel-report.json\"").body(service.analyze(input).incident());}
    private ResponseEntity<String> download(String body,String type,String name) {return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE,type).header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+name+"\"").body(body);}
    private String read(String name)throws IOException {return new ClassPathResource("samples/"+name).getContentAsString(StandardCharsets.UTF_8);}
}
