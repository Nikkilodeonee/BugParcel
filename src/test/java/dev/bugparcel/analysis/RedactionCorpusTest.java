package dev.bugparcel.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.bugparcel.export.ReportExporter;
import dev.bugparcel.model.Models.*;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Regression corpus for automatic redaction. The numbers it produces describe these hand-written fixtures only, which is why
 * they are reported per category, with adversarial cases and known limitations listed separately.
 */
class RedactionCorpusTest {
    private static final class Counts { int tp, fp, fn, cases; }

    @Test void measuresPrecisionRecallAndExportRemovalOnLabeledSyntheticCases() throws Exception {
        var mapper = new ObjectMapper();
        var service = new IncidentService(new HarParser(mapper), new LogParser(mapper), new Correlator(), mapper);
        var corpus = mapper.readTree(getClass().getResourceAsStream("/redaction/corpus.json"));
        String har = "{\"log\":{\"entries\":[{\"request\":{\"method\":\"GET\",\"url\":\"https://example.test\",\"headers\":[]},\"response\":{\"status\":200,\"headers\":[]}}]}}";
        Map<String,Counts> byCategory = new TreeMap<>();
        Counts total = new Counts();
        int negativeCases = 0, adversarialCases = 0;
        var knownLimitations = mapper.createArrayNode();
        List<String> errors = new ArrayList<>();
        for (var item : corpus.path("cases")) {
            String id = item.path("id").asText(), category = item.path("category").asText("UNCATEGORIZED");
            boolean known = item.path("knownLimitation").asBoolean(false);
            Set<String> expected = new LinkedHashSet<>();
            item.path("expected").forEach(n -> expected.add(n.asText()));
            var input = new AnalysisInput(har, mapper.createObjectNode().put("message", item.path("text").asText()).toString(), "Synthetic corpus",
                null, List.of(), false, Set.of(), Set.of(), false, item.path("profile").asText(), null, null);
            var result = service.analyze(input);
            Map<String,String> actual = new LinkedHashMap<>();
            result.findings().stream().filter(f -> f.replacements() > 0)
                .forEach(f -> actual.put(f.value(), f.categories().isEmpty() ? "UNCATEGORIZED" : f.categories().get(0)));

            List<String> caseErrors = new ArrayList<>();
            Counts caseTotals = new Counts();
            Map<String,Counts> caseCategories = new HashMap<>();
            for (var entry : actual.entrySet()) {
                if (expected.contains(entry.getKey())) { caseTotals.tp++; caseCategories.computeIfAbsent(category, k -> new Counts()).tp++; }
                else { caseTotals.fp++; caseCategories.computeIfAbsent(entry.getValue(), k -> new Counts()).fp++; caseErrors.add(id + ": unexpected redaction"); }
            }
            for (String value : expected) if (!actual.containsKey(value)) {
                caseTotals.fn++; caseCategories.computeIfAbsent(category, k -> new Counts()).fn++; caseErrors.add(id + ": missed redaction");
            }

            if (known) {
                if (caseErrors.isEmpty()) errors.add(id + ": known limitation now passes; remove the knownLimitation flag and count it");
                else knownLimitations.add(mapper.createObjectNode().put("id", id).put("category", category)
                    .put("behavior", caseErrors.get(0).substring(id.length() + 2)));
                continue;
            }

            total.cases++;
            byCategory.computeIfAbsent(category, k -> new Counts()).cases++;
            if (expected.isEmpty()) negativeCases++;
            if (item.path("adversarial").asBoolean(false)) adversarialCases++;
            total.tp += caseTotals.tp; total.fp += caseTotals.fp; total.fn += caseTotals.fn;
            caseCategories.forEach((name, counts) -> {
                var target = byCategory.computeIfAbsent(name, k -> new Counts());
                target.tp += counts.tp; target.fp += counts.fp; target.fn += counts.fn;
            });
            errors.addAll(caseErrors);
            if (!expected.isEmpty()) {
                var exporter = new ReportExporter();
                for (String report : List.of(mapper.writeValueAsString(result.incident()), exporter.html(result.incident()), exporter.markdown(result.incident())))
                    for (String value : expected) assertThat(report).as(id).doesNotContain(value);
            }
        }

        var metrics = mapper.createObjectNode()
            .put("scope", "Hand-written synthetic regression fixtures; not real-world accuracy or a security guarantee")
            .put("cases", total.cases).put("negativeCases", negativeCases).put("adversarialCases", adversarialCases)
            .put("truePositives", total.tp).put("falsePositives", total.fp).put("falseNegatives", total.fn);
        ratios(metrics, total);
        ObjectNode categories = metrics.putObject("byCategory");
        byCategory.forEach((name, counts) -> {
            ObjectNode node = categories.putObject(name);
            node.put("cases", counts.cases).put("truePositives", counts.tp).put("falsePositives", counts.fp).put("falseNegatives", counts.fn);
            ratios(node, counts);
        });
        metrics.set("knownLimitations", knownLimitations);
        Files.createDirectories(Path.of("target"));
        Files.writeString(Path.of("target/redaction-corpus-metrics.json"), mapper.writerWithDefaultPrettyPrinter().writeValueAsString(metrics));
        System.out.printf(Locale.ROOT, "Redaction regression corpus: %d cases (%d adversarial), TP=%d FP=%d FN=%d, %d known limitations%n",
            total.cases, adversarialCases, total.tp, total.fp, total.fn, knownLimitations.size());
        assertThat(errors).isEmpty();
        assertThat(knownLimitations.size()).as("known limitations stay visible in the metrics").isGreaterThan(0);
        assertThat(metrics.path("precision").asDouble()).isGreaterThanOrEqualTo(0.98);
        assertThat(metrics.path("recall").asDouble()).isGreaterThanOrEqualTo(0.98);
    }

    private static void ratios(ObjectNode node, Counts counts) {
        if (counts.tp + counts.fp == 0) node.putNull("precision"); else node.put("precision", (double) counts.tp / (counts.tp + counts.fp));
        if (counts.tp + counts.fn == 0) node.putNull("recall"); else node.put("recall", (double) counts.tp / (counts.tp + counts.fn));
    }
}
