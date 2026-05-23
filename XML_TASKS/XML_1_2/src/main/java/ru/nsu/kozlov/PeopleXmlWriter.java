package ru.nsu.kozlov;

import javax.xml.stream.*;
import java.io.*;
import java.util.*;

public class PeopleXmlWriter implements PeopleWriter {

    @Override
    public void write(Map<String, Person> registry, OutputStream out) throws Exception {
        XMLOutputFactory factory = XMLOutputFactory.newInstance();
        XMLStreamWriter w = factory.createXMLStreamWriter(
                new BufferedOutputStream(out), "UTF-8");

        w.writeStartDocument("UTF-8", "1.0");
        w.writeCharacters("\n");
        w.writeStartElement("people");
        w.writeAttribute("count", String.valueOf(registry.size()));
        w.writeCharacters("\n");

        for (Person p : registry.values()) {
            writePerson(w, p);
        }

        w.writeEndElement();
        w.writeEndDocument();
        w.flush();
        w.close();
    }

    private void writePerson(XMLStreamWriter w, Person p) throws XMLStreamException {
        w.writeCharacters("  ");
        w.writeStartElement("person");
        if (p.getId() != null) w.writeAttribute("id", p.getId());
        w.writeCharacters("\n");

        if (p.getFirstName() != null || p.getLastName() != null) {
            indent(w, 2); w.writeStartElement("name"); w.writeCharacters("\n");
            if (p.getFirstName() != null) writeTextElement(w, "first", p.getFirstName(), 3);
            if (p.getLastName()  != null) writeTextElement(w, "last",  p.getLastName(),  3);
            indent(w, 2); w.writeEndElement(); w.writeCharacters("\n");
        }

        if (p.getGender() != null) {
            writeTextElement(w, "gender", p.getGender(), 2);
        }

        if (p.getSpouseRef() != null || p.getSpouseName() != null) {
            indent(w, 2); w.writeEmptyElement("spouse");
            if (p.getSpouseRef() != null)  w.writeAttribute("ref",  p.getSpouseRef());
            if (p.getSpouseName() != null) w.writeAttribute("name", p.getSpouseName());
            w.writeCharacters("\n");
        }

        boolean hasParents = !p.getParentRefs().isEmpty()
                || p.getFatherName() != null || p.getMotherName() != null;
        if (hasParents) {
            indent(w, 2); w.writeStartElement("parents"); w.writeCharacters("\n");
            for (String ref : p.getParentRefs()) {
                indent(w, 3); w.writeEmptyElement("parent");
                w.writeAttribute("ref", ref); w.writeCharacters("\n");
            }
            if (p.getFatherName() != null) writeTextElement(w, "father", p.getFatherName(), 3);
            if (p.getMotherName() != null) writeTextElement(w, "mother", p.getMotherName(), 3);
            indent(w, 2); w.writeEndElement(); w.writeCharacters("\n");
        }

        boolean hasChildren = !p.getSonRefs().isEmpty() || !p.getDaughterRefs().isEmpty()
                || !p.getChildNames().isEmpty() || p.getDeclaredChildrenCount() >= 0;
        if (hasChildren) {
            indent(w, 2); w.writeStartElement("children");
            if (p.getDeclaredChildrenCount() >= 0)
                w.writeAttribute("declared", String.valueOf(p.getDeclaredChildrenCount()));
            w.writeCharacters("\n");
            for (String ref : p.getSonRefs()) {
                indent(w, 3); w.writeEmptyElement("son");
                w.writeAttribute("ref", ref); w.writeCharacters("\n");
            }
            for (String ref : p.getDaughterRefs()) {
                indent(w, 3); w.writeEmptyElement("daughter");
                w.writeAttribute("ref", ref); w.writeCharacters("\n");
            }
            for (String name : p.getChildNames()) {
                writeTextElement(w, "child", name, 3);
            }
            indent(w, 2); w.writeEndElement(); w.writeCharacters("\n");
        }

        boolean hasSiblings = !p.getSiblingRefs().isEmpty() || !p.getBrotherNames().isEmpty()
                || !p.getSisterNames().isEmpty() || p.getDeclaredSiblingsCount() >= 0;
        if (hasSiblings) {
            indent(w, 2); w.writeStartElement("siblings");
            if (p.getDeclaredSiblingsCount() >= 0)
                w.writeAttribute("declared", String.valueOf(p.getDeclaredSiblingsCount()));
            w.writeCharacters("\n");
            for (String ref : p.getSiblingRefs()) {
                indent(w, 3); w.writeEmptyElement("sibling");
                w.writeAttribute("ref", ref); w.writeCharacters("\n");
            }
            for (String name : p.getBrotherNames()) {
                writeTextElement(w, "brother", name, 3);
            }
            for (String name : p.getSisterNames()) {
                writeTextElement(w, "sister", name, 3);
            }
            indent(w, 2); w.writeEndElement(); w.writeCharacters("\n");
        }

        if (!p.getWarnings().isEmpty()) {
            indent(w, 2); w.writeStartElement("warnings"); w.writeCharacters("\n");
            for (String warn : p.getWarnings()) {
                writeTextElement(w, "warning", warn, 3);
            }
            indent(w, 2); w.writeEndElement(); w.writeCharacters("\n");
        }

        w.writeCharacters("  ");
        w.writeEndElement();
        w.writeCharacters("\n");
    }

    private void writeTextElement(XMLStreamWriter w, String tag, String text, int depth)
            throws XMLStreamException {
        indent(w, depth);
        w.writeStartElement(tag);
        w.writeCharacters(text);
        w.writeEndElement();
        w.writeCharacters("\n");
    }

    private void indent(XMLStreamWriter w, int depth) throws XMLStreamException {
        w.writeCharacters("  ".repeat(depth));
    }
}