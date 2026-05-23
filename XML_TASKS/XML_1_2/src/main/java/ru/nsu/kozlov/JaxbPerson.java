package ru.nsu.kozlov;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class JaxbPerson {

    @XmlAttribute(name = "id")
    @XmlID
    private String id;

    @XmlElement(name = "name")
    private JaxbName name;

    @XmlElement(name = "gender")
    private String gender;

    @XmlElement(name = "spouse")
    private JaxbSpouse spouse;

    @XmlElement(name = "parents")
    private JaxbParents parents;

    @XmlElement(name = "children")
    private JaxbChildren children;

    @XmlElement(name = "siblings")
    private JaxbSiblings siblings;

    @XmlElement(name = "warnings")
    private JaxbWarnings warnings;

    public JaxbPerson() {}

    public String getId()                        { return id; }
    public void setId(String id)                 { this.id = id; }
    public JaxbName getName()                    { return name; }
    public void setName(JaxbName n)              { this.name = n; }
    public String getGender()                    { return gender; }
    public void setGender(String g)              { this.gender = g; }
    public JaxbSpouse getSpouse()                { return spouse; }
    public void setSpouse(JaxbSpouse s)          { this.spouse = s; }
    public JaxbParents getParents()              { return parents; }
    public void setParents(JaxbParents p)        { this.parents = p; }
    public JaxbChildren getChildren()            { return children; }
    public void setChildren(JaxbChildren c)      { this.children = c; }
    public JaxbSiblings getSiblings()            { return siblings; }
    public void setSiblings(JaxbSiblings s)      { this.siblings = s; }
    public JaxbWarnings getWarnings()            { return warnings; }
    public void setWarnings(JaxbWarnings w)      { this.warnings = w; }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbName {
        @XmlElement(name = "first") private String first;
        @XmlElement(name = "last")  private String last;
        public JaxbName() {}
        public JaxbName(String first, String last) { this.first = first; this.last = last; }
        public String getFirst()           { return first; }
        public void setFirst(String f)     { this.first = f; }
        public String getLast()            { return last; }
        public void setLast(String l)      { this.last = l; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbSpouse {
        @XmlAttribute(name = "ref")
        @XmlSchemaType(name = "IDREF")
        private String ref;

        @XmlAttribute(name = "name")
        private String name;

        public JaxbSpouse() {}
        public JaxbSpouse(String ref, String name) { this.ref = ref; this.name = name; }
        public String getRef()             { return ref; }
        public void setRef(String r)       { this.ref = r; }
        public String getName()            { return name; }
        public void setName(String n)      { this.name = n; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbParents {
        @XmlElement(name = "parent") private List<JaxbRef>  parentRefs = new ArrayList<>();
        @XmlElement(name = "father") private String         fatherName;
        @XmlElement(name = "mother") private String         motherName;
        public JaxbParents() {}
        public List<JaxbRef> getParentRefs()         { return parentRefs; }
        public String getFatherName()                { return fatherName; }
        public void setFatherName(String n)          { this.fatherName = n; }
        public String getMotherName()                { return motherName; }
        public void setMotherName(String n)          { this.motherName = n; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbChildren {
        @XmlAttribute(name = "declared") private Integer       declared;
        @XmlElement(name = "son")        private List<JaxbRef> sons      = new ArrayList<>();
        @XmlElement(name = "daughter")   private List<JaxbRef> daughters = new ArrayList<>();
        @XmlElement(name = "child")      private List<String>  childNames= new ArrayList<>();
        public JaxbChildren() {}
        public Integer getDeclared()               { return declared; }
        public void setDeclared(Integer d)         { this.declared = d; }
        public List<JaxbRef> getSons()             { return sons; }
        public List<JaxbRef> getDaughters()        { return daughters; }
        public List<String> getChildNames()        { return childNames; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbSiblings {
        @XmlAttribute(name = "declared") private Integer       declared;
        @XmlElement(name = "sibling")    private List<JaxbRef> siblingRefs  = new ArrayList<>();
        @XmlElement(name = "brother")    private List<String>  brotherNames = new ArrayList<>();
        @XmlElement(name = "sister")     private List<String>  sisterNames  = new ArrayList<>();
        public JaxbSiblings() {}
        public Integer getDeclared()                { return declared; }
        public void setDeclared(Integer d)          { this.declared = d; }
        public List<JaxbRef> getSiblingRefs()       { return siblingRefs; }
        public List<String> getBrotherNames()       { return brotherNames; }
        public List<String> getSisterNames()        { return sisterNames; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbWarnings {
        @XmlElement(name = "warning") private List<String> items = new ArrayList<>();
        public JaxbWarnings() {}
        public List<String> getItems()             { return items; }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class JaxbRef {
        @XmlAttribute(name = "ref")
        @XmlSchemaType(name = "IDREF")
        private String ref;
        public JaxbRef() {}
        public JaxbRef(String ref) { this.ref = ref; }
        public String getRef()        { return ref; }
        public void setRef(String r)  { this.ref = r; }
    }
}