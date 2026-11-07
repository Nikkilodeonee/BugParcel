package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class RedactionCorpusTest {
    @Test void measuresPrecisionRecallAndExportRemovalOnLabeledSyntheticCases() throws Exception {
        var mapper=new ObjectMapper();
        var service=new IncidentService(new HarParser(mapper),new LogParser(mapper),new Correlator(),mapper);
        var corpus=mapper.readTree(getClass().getResourceAsStream("/redaction/corpus.json"));
        String har="{\"log\":{\"entries\":[{\"request\":{\"method\":\"GET\",\"url\":\"https://example.test\",\"headers\":[]},\"response\":{\"status\":200,\"headers\":[]}}]}}";
        int tp=0,fp=0,fn=0,negativeCases=0;
        List<String> errors=new ArrayList<>();
        for(var item:corpus.path("cases")) {
            Set<String> expected=new HashSet<>();item.path("expected").forEach(n->expected.add(n.asText()));
            if(expected.isEmpty())negativeCases++;
            var input=new AnalysisInput(har,mapper.createObjectNode().put("message",item.path("text").asText()).toString(),"Synthetic corpus",null,List.of(),false,Set.of(),Set.of(),false,item.path("profile").asText(),null,null);
            var result=service.analyze(input);
            Set<String> actual=new HashSet<>();
            result.findings().stream().filter(f->f.replacements()>0).forEach(f->actual.add(f.value()));
            for(String value:actual)if(expected.contains(value))tp++;else{fp++;errors.add(item.path("id").asText()+": unexpected redaction");}
            for(String value:expected)if(!actual.contains(value)){fn++;errors.add(item.path("id").asText()+": missed redaction");}
            if(!expected.isEmpty()) {
                var exporter=new dev.bugparcel.export.ReportExporter();
                for(String report:List.of(mapper.writeValueAsString(result.incident()),exporter.html(result.incident()),exporter.markdown(result.incident())))
                    for(String value:expected)assertThat(report).as(item.path("id").asText()).doesNotContain(value);
            }
        }
        double precision=tp+fp==0?1:(double)tp/(tp+fp),recall=tp+fn==0?1:(double)tp/(tp+fn);
        var metrics=mapper.createObjectNode().put("scope","Synthetic automatic-redaction fixtures; not real-world accuracy or a security guarantee")
            .put("cases",corpus.path("cases").size()).put("negativeCases",negativeCases).put("truePositives",tp).put("falsePositives",fp).put("falseNegatives",fn).put("precision",precision).put("recall",recall);
        Files.createDirectories(Path.of("target"));
        Files.writeString(Path.of("target/redaction-corpus-metrics.json"),mapper.writerWithDefaultPrettyPrinter().writeValueAsString(metrics));
        System.out.printf(Locale.ROOT,"Synthetic redaction corpus: %d cases, TP=%d FP=%d FN=%d precision=%.4f recall=%.4f%n",corpus.path("cases").size(),tp,fp,fn,precision,recall);
        assertThat(errors).isEmpty();
        assertThat(precision).isGreaterThanOrEqualTo(0.98);assertThat(recall).isGreaterThanOrEqualTo(0.98);
    }
}
