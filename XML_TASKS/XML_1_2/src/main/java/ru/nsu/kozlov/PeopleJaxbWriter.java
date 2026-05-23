package ru.nsu.kozlov;

import ru.nsu.kozlov.JaxbPerson.*;

import javax.xml.bind.*;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.XMLConstants;
import java.io.*;
import java.net.URL;
import java.util.*;

public class PeopleJaxbWriter implements PeopleWriter {

    private final String schemaPath;

    public PeopleJaxbWriter(String schemaPath) {
        this.schemaPath = schemaPath;
    }

    @Override
    public void write(Map<String, Person> registry, OutputStream out) throws Exception {
        JaxbPeople people = toJaxb(registry);

        JAXBContext ctx = JAXBContext.newInstance(JaxbPeople.class);
        Marshaller marshaller = ctx.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");

        if (schemaPath != null) {
            Schema schema = loadSchema(schemaPath);
            marshaller.setSchema(schema);
            marshaller.setEventHandler(new ValidationEventHandler() {
                @Override
                public boolean handleEvent(ValidationEvent event) {
                    String severity = switch (event.getSeverity()) {
                        case ValidationEvent.WARNING      -> "WARN ";
                        case ValidationEvent.ERROR        -> "ERROR";
                        case ValidationEvent.FATAL_ERROR  -> "FATAL";
                        default                           -> "?????";
                    };
                    System.err.printf("[XSD %s] line %d: %s%n",
                            severity,
                            event.getLocator() != null ? event.getLocator().getLineNumber() : -1,
                            event.getMessage());
                    return event.getSeverity() != ValidationEvent.FATAL_ERROR;
                }
            });
            System.out.println("XSD validation enabled: " + schemaPath);
        } else {
            System.out.println("XSD validation skipped (no schema path provided)");
        }

        marshaller.marshal(people, new BufferedOutputStream(out));
    }

    private JaxbPeople toJaxb(Map<String, Person> registry) {
        JaxbPeople root = new JaxbPeople();
        root.setCount(registry.size());

        Set<String> knownIds = new HashSet<>();
        for (Person p : registry.values()) {
            if (p.getId() != null) knownIds.add(p.getId());
        }

        for (Person p : registry.values()) {
            root.getPersons().add(toJaxbPerson(p, knownIds));
        }
        return root;
    }

    private JaxbPerson toJaxbPerson(Person p, Set<String> knownIds) {
        JaxbPerson jp = new JaxbPerson();

        jp.setId(p.getId() != null ? p.getId() : generateAnonymousId(p));

        if (p.getFirstName() != null || p.getLastName() != null) {
            jp.setName(new JaxbName(p.getFirstName(), p.getLastName()));
        }

        jp.setGender(p.getGender());

        if (p.getSpouseRef() != null || p.getSpouseName() != null) {
            String safeRef = safeIdRef(p.getSpouseRef(), knownIds);
            jp.setSpouse(new JaxbSpouse(safeRef, p.getSpouseName()));
        }

        boolean hasParents = !p.getParentRefs().isEmpty()
                || p.getFatherName() != null || p.getMotherName() != null;
        if (hasParents) {
            JaxbParents parents = new JaxbParents();
            for (String ref : p.getParentRefs()) {
                String safe = safeIdRef(ref, knownIds);
                if (safe != null) parents.getParentRefs().add(new JaxbRef(safe));
            }
            parents.setFatherName(p.getFatherName());
            parents.setMotherName(p.getMotherName());
            jp.setParents(parents);
        }

        boolean hasChildren = !p.getSonRefs().isEmpty() || !p.getDaughterRefs().isEmpty()
                || !p.getChildNames().isEmpty() || p.getDeclaredChildrenCount() >= 0;
        if (hasChildren) {
            JaxbChildren children = new JaxbChildren();
            if (p.getDeclaredChildrenCount() >= 0)
                children.setDeclared(p.getDeclaredChildrenCount());
            for (String ref : p.getSonRefs()) {
                String safe = safeIdRef(ref, knownIds);
                if (safe != null) children.getSons().add(new JaxbRef(safe));
            }
            for (String ref : p.getDaughterRefs()) {
                String safe = safeIdRef(ref, knownIds);
                if (safe != null) children.getDaughters().add(new JaxbRef(safe));
            }
            children.getChildNames().addAll(p.getChildNames());
            jp.setChildren(children);
        }

        boolean hasSiblings = !p.getSiblingRefs().isEmpty() || !p.getBrotherNames().isEmpty()
                || !p.getSisterNames().isEmpty() || p.getDeclaredSiblingsCount() >= 0;
        if (hasSiblings) {
            JaxbSiblings siblings = new JaxbSiblings();
            if (p.getDeclaredSiblingsCount() >= 0)
                siblings.setDeclared(p.getDeclaredSiblingsCount());
            for (String ref : p.getSiblingRefs()) {
                String safe = safeIdRef(ref, knownIds);
                if (safe != null) siblings.getSiblingRefs().add(new JaxbRef(safe));
            }
            siblings.getBrotherNames().addAll(p.getBrotherNames());
            siblings.getSisterNames().addAll(p.getSisterNames());
            jp.setSiblings(siblings);
        }

        if (!p.getWarnings().isEmpty()) {
            JaxbWarnings w = new JaxbWarnings();
            w.getItems().addAll(p.getWarnings());
            jp.setWarnings(w);
        }

        return jp;
    }

    private String safeIdRef(String ref, Set<String> knownIds) {
        if (ref == null) return null;
        return knownIds.contains(ref) ? ref : null;
    }

    private int anonCounter = 0;
    private String generateAnonymousId(Person p) {
        String base = p.getDisplayName().replaceAll("[^A-Za-z0-9]", "_");
        return "ANON_" + base + "_" + (++anonCounter);
    }

    private Schema loadSchema(String path) throws Exception {
        SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        File f = new File(path);
        if (f.exists()) return sf.newSchema(f);
        URL url = getClass().getClassLoader().getResource(path);
        if (url != null) return sf.newSchema(url);
        throw new FileNotFoundException("XSD schema not found: " + path);
    }
}