package ru.nsu.kozlov;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

public class Main {

    public static void main(String[] args) throws Exception {
        String inputPath  = args.length > 0 ? args[0] : "people.xml";
        String outputPath = args.length > 1 ? args[1] : "people-merged.xml";
        String mode       = args.length > 2 ? args[2] : "stax";
        String schemaPath = args.length > 3 ? args[3] : null;

        System.out.println("=== People XML Parser ===");
        System.out.println("Input  : " + inputPath);
        System.out.println("Output : " + outputPath);
        System.out.println("Mode   : " + mode);

        long t0 = System.currentTimeMillis();
        PeopleStaxParser parser = new PeopleStaxParser();
        Map<String, Person> registry;
        try (InputStream is = new BufferedInputStream(Files.newInputStream(Paths.get(inputPath)))) {
            registry = parser.parse(is);
        }
        System.out.printf("Parsed %,d unique persons in %d ms%n",
                registry.size(), System.currentTimeMillis() - t0);

        printStats(registry);

        PeopleWriter writer = switch (mode.toLowerCase()) {
            case "jaxb" -> new PeopleJaxbWriter(schemaPath);
            default     -> new PeopleXmlWriter();
        };

        t0 = System.currentTimeMillis();
        try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(Paths.get(outputPath)))) {
            writer.write(registry, os);
        }
        System.out.printf("Written (%s) to '%s' in %d ms%n",
                mode, outputPath, System.currentTimeMillis() - t0);
    }

    private static void printStats(Map<String, Person> registry) {
        Collection<Person> persons = registry.values();

        long withId       = persons.stream().filter(p -> p.getId() != null).count();
        long withName     = persons.stream().filter(p -> p.getFirstName() != null || p.getLastName() != null).count();
        long withGender   = persons.stream().filter(p -> p.getGender() != null).count();
        long withSpouse   = persons.stream().filter(p -> p.getSpouseRef() != null || p.getSpouseName() != null).count();
        long withParents  = persons.stream().filter(p -> !p.getParentRefs().isEmpty() || p.getFatherName() != null || p.getMotherName() != null).count();
        long withChildren = persons.stream().filter(p -> !p.getSonRefs().isEmpty() || !p.getDaughterRefs().isEmpty() || !p.getChildNames().isEmpty() || p.getDeclaredChildrenCount() >= 0).count();
        long withSiblings = persons.stream().filter(p -> !p.getSiblingRefs().isEmpty() || !p.getBrotherNames().isEmpty() || !p.getSisterNames().isEmpty() || p.getDeclaredSiblingsCount() >= 0).count();
        long withWarnings = persons.stream().filter(p -> !p.getWarnings().isEmpty()).count();

        System.out.println("\n── Statistics ───────────────────────────────────");
        System.out.printf("  Total unique persons : %,d%n", registry.size());
        System.out.printf("  Have P-id            : %,d%n", withId);
        System.out.printf("  Have name info       : %,d%n", withName);
        System.out.printf("  Have gender          : %,d%n", withGender);
        System.out.printf("  Have spouse info     : %,d%n", withSpouse);
        System.out.printf("  Have parent info     : %,d%n", withParents);
        System.out.printf("  Have children info   : %,d%n", withChildren);
        System.out.printf("  Have siblings info   : %,d%n", withSiblings);
        System.out.printf("  With warnings        : %,d%n", withWarnings);

        List<Person> warned = persons.stream()
                .filter(p -> !p.getWarnings().isEmpty()).limit(5)
                .collect(Collectors.toList());
        if (!warned.isEmpty()) {
            System.out.println("\n── Sample consistency warnings ──────────────────");
            warned.forEach(p -> System.out.printf("  %-14s  %s%n",
                    p.getId() != null ? p.getId() : p.getDisplayName(), p.getWarnings()));
        }
        System.out.println("─────────────────────────────────────────────────\n");
    }
}