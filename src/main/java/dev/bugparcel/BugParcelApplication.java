package dev.bugparcel;

import com.fasterxml.jackson.core.StreamReadConstraints;
import dev.bugparcel.cli.Cli;
import java.nio.file.Paths;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class BugParcelApplication {
    public static void main(String[] args) {
        // Command-line commands never start Spring or open a port.
        if (Cli.handles(args) && !args[0].equals("serve")) {
            System.exit(Cli.run(args, System.in, System.out, System.err, Paths.get("").toAbsolutePath()));
        }
        String[] serverArgs = args.length > 0 && args[0].equals("serve") ? Cli.serverArguments(args) : args;
        SpringApplication.run(BugParcelApplication.class, serverArgs);
    }

    @Bean
    Jackson2ObjectMapperBuilderCustomizer jsonLimits() {
        return builder -> builder.postConfigurer(mapper -> mapper.getFactory().setStreamReadConstraints(
            StreamReadConstraints.builder().maxStringLength(12_000_000).maxNestingDepth(100).build()));
    }
}
