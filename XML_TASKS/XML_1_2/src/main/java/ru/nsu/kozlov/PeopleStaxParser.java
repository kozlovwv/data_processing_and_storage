package ru.nsu.kozlov;

import javax.xml.stream.*;
import java.io.*;
import java.util.*;

public class PeopleStaxParser {

    private final Map<String, Person> registry = new LinkedHashMap<>();
    private final Map<String, String> nameToKey = new HashMap<>();

    public Map<String, Person> parse(InputStream is) throws XMLStreamException {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_COALESCING, Boolean.TRUE);
        XMLStreamReader reader = factory.createXMLStreamReader(is);

        Person current = null;
        String insideChildren = null;
        String insideSiblings = null;
        Deque<String> elementStack = new ArrayDeque<>();

        while (reader.hasNext()) {
            int event = reader.next();

            switch (event) {

                case XMLStreamConstants.START_ELEMENT: {
                    String localName = reader.getLocalName();
                    elementStack.push(localName);

                    if ("person".equals(localName)) {
                        current = new Person();
                        insideChildren = null;
                        insideSiblings = null;

                        String attrId = reader.getAttributeValue(null, "id");
                        if (attrId != null) current.setId(attrId.trim());

                        String attrName = reader.getAttributeValue(null, "name");
                        if (attrName != null) {
                            parseName(attrName.trim(), current);
                        }
                        break;
                    }

                    if (current == null) break;

                    switch (localName) {
                        case "id": {
                            String v = attr(reader, "value");
                            if (v != null && current.getId() == null) current.setId(v.trim());
                            break;
                        }
                        case "firstname": {
                            String v = attr(reader, "value");
                            if (v != null && current.getFirstName() == null)
                                current.setFirstName(v);
                            break;
                        }
                        case "surname":
                        case "family-name": {
                            String v = attr(reader, "value");
                            if (v != null && current.getLastName() == null)
                                current.setLastName(v);
                            break;
                        }
                        case "gender": {
                            String v = attr(reader, "value");
                            if (v != null) current.setGender(v);
                            break;
                        }
                        case "wife":
                        case "husband":
                        case "spouce": {
                            String v = attr(reader, "value");
                            if (v != null && !v.isEmpty() && !v.equalsIgnoreCase("NONE")) {
                                if (v.startsWith("P")) current.setSpouseRef(v.trim());
                                else                   current.setSpouseName(v);
                            }
                            break;
                        }
                        case "parent": {
                            String v = attr(reader, "value");
                            if (v != null && !v.equalsIgnoreCase("UNKNOWN"))
                                current.getParentRefs().add(v.trim());
                            break;
                        }
                        case "children": {
                            insideChildren = "children";
                            break;
                        }
                        case "children-number": {
                            String v = attr(reader, "value");
                            if (v != null && current.getDeclaredChildrenCount() < 0)
                                current.setDeclaredChildrenCount(parseInt(v));
                            break;
                        }
                        case "son": {
                            if (insideChildren != null) {
                                String refId = attr(reader, "id");
                                if (refId != null) current.getSonRefs().add(refId.trim());
                            }
                            break;
                        }
                        case "daughter": {
                            if (insideChildren != null) {
                                String refId = attr(reader, "id");
                                if (refId != null) current.getDaughterRefs().add(refId.trim());
                            }
                            break;
                        }
                        case "siblings": {
                            insideSiblings = "siblings";
                            String val = attr(reader, "val");
                            if (val != null) {
                                for (String ref : val.trim().split("\\s+"))
                                    if (!ref.isEmpty()) current.getSiblingRefs().add(ref);
                            }
                            break;
                        }
                        case "siblings-number": {
                            String v = attr(reader, "value");
                            if (v != null && current.getDeclaredSiblingsCount() < 0)
                                current.setDeclaredSiblingsCount(parseInt(v));
                            break;
                        }
                        case "brother":
                        case "sister":
                            break;
                    }
                    break;
                }

                case XMLStreamConstants.CHARACTERS: {
                    if (current == null) break;
                    String text = reader.getText().trim();
                    if (text.isEmpty()) break;

                    String top = elementStack.isEmpty() ? "" : elementStack.peek();
                    switch (top) {
                        case "firstname":
                            if (current.getFirstName() == null) current.setFirstName(text);
                            break;
                        case "surname":
                        case "family-name":
                            if (current.getLastName() == null) current.setLastName(text);
                            break;
                        case "first":
                            if (current.getFirstName() == null) current.setFirstName(text);
                            break;
                        case "family":
                            if (current.getLastName() == null) current.setLastName(text);
                            break;
                        case "gender":
                            current.setGender(text);
                            break;
                        case "parent":
                            if (!text.equalsIgnoreCase("UNKNOWN"))
                                current.getParentRefs().add(text);
                            break;
                        case "father":
                            if (current.getFatherName() == null) current.setFatherName(text);
                            break;
                        case "mother":
                            if (current.getMotherName() == null) current.setMotherName(text);
                            break;
                        case "child":
                            current.getChildNames().add(text);
                            break;
                        case "brother":
                            current.getBrotherNames().add(text);
                            break;
                        case "sister":
                            current.getSisterNames().add(text);
                            break;
                    }
                    break;
                }

                case XMLStreamConstants.END_ELEMENT: {
                    String localName = reader.getLocalName();
                    if (!elementStack.isEmpty()) elementStack.pop();

                    if ("children".equals(localName)) insideChildren = null;
                    if ("siblings".equals(localName)) insideSiblings = null;

                    if ("person".equals(localName) && current != null) {
                        register(current);
                        current = null;
                    }
                    break;
                }
            }
        }
        reader.close();

        registry.values().forEach(Person::validate);

        return Collections.unmodifiableMap(registry);
    }

    private void register(Person p) {
        String key = canonicalKey(p);
        Person existing = registry.get(key);
        if (existing == null) {
            registry.put(key, p);
            String dn = p.getDisplayName();
            if (p.getId() != null) nameToKey.putIfAbsent(dn, key);
        } else {
            existing.mergeFrom(p);
        }
    }

    private String canonicalKey(Person p) {
        if (p.getId() != null) return p.getId();
        return "name:" + p.getDisplayName();
    }

    private static void parseName(String fullName, Person p) {
        if (fullName == null || fullName.isEmpty()) return;
        String[] parts = fullName.trim().split("\\s+", 2);
        if (p.getFirstName() == null) p.setFirstName(parts[0]);
        if (parts.length > 1 && p.getLastName() == null) p.setLastName(parts[1]);
    }

    private static String attr(XMLStreamReader r, String name) {
        String v = r.getAttributeValue(null, name);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : null;
    }

    private static int parseInt(String s) {
        try { return Integer.parseInt(s.trim()); }
        catch (NumberFormatException e) { return -1; }
    }
}