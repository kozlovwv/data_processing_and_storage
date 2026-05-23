package ru.nsu.kozlov;

import java.util.*;

public class Person {

    private String id;
    private String firstName;
    private String lastName;
    private String gender;

    private String spouseRef;
    private String spouseName;

    private final Set<String> parentRefs = new LinkedHashSet<>();
    private String fatherName;
    private String motherName;

    private final Set<String> sonRefs      = new LinkedHashSet<>();
    private final Set<String> daughterRefs = new LinkedHashSet<>();
    private final Set<String> childNames   = new LinkedHashSet<>();
    private int declaredChildrenCount = -1;

    private final Set<String> siblingRefs  = new LinkedHashSet<>();
    private final Set<String> brotherNames = new LinkedHashSet<>();
    private final Set<String> sisterNames  = new LinkedHashSet<>();
    private int declaredSiblingsCount = -1;

    private final List<String> warnings = new ArrayList<>();

    public void mergeFrom(Person other) {
        if (this.id == null && other.id != null)               this.id = other.id;
        if (this.firstName == null && other.firstName != null) this.firstName = other.firstName;
        if (this.lastName  == null && other.lastName  != null) this.lastName  = other.lastName;
        if (this.gender    == null && other.gender    != null) this.gender    = other.gender;
        if (this.spouseRef == null && other.spouseRef != null) this.spouseRef = other.spouseRef;
        if (this.spouseName== null && other.spouseName!= null) this.spouseName= other.spouseName;
        if (this.fatherName== null && other.fatherName!= null) this.fatherName= other.fatherName;
        if (this.motherName== null && other.motherName!= null) this.motherName= other.motherName;

        this.parentRefs.addAll(other.parentRefs);
        this.sonRefs.addAll(other.sonRefs);
        this.daughterRefs.addAll(other.daughterRefs);
        this.childNames.addAll(other.childNames);
        this.siblingRefs.addAll(other.siblingRefs);
        this.brotherNames.addAll(other.brotherNames);
        this.sisterNames.addAll(other.sisterNames);

        if (this.declaredChildrenCount < 0 && other.declaredChildrenCount >= 0)
            this.declaredChildrenCount = other.declaredChildrenCount;
        if (this.declaredSiblingsCount < 0 && other.declaredSiblingsCount >= 0)
            this.declaredSiblingsCount = other.declaredSiblingsCount;
    }

    public void validate() {
        if (declaredChildrenCount >= 0) {
            int actual = sonRefs.size() + daughterRefs.size() + childNames.size();
            if (actual > declaredChildrenCount) {
                warnings.add(String.format(
                        "children-number=%d but %d child references found", declaredChildrenCount, actual));
            }
        }
        if (declaredSiblingsCount >= 0) {
            int actual = siblingRefs.size() + brotherNames.size() + sisterNames.size();
            if (actual > declaredSiblingsCount) {
                warnings.add(String.format(
                        "siblings-number=%d but %d sibling references found", declaredSiblingsCount, actual));
            }
        }
    }

    public String getDisplayName() {
        StringBuilder sb = new StringBuilder();
        if (firstName != null) sb.append(firstName.trim());
        if (lastName  != null) { if (sb.length() > 0) sb.append(' '); sb.append(lastName.trim()); }
        return sb.length() > 0 ? sb.toString() : (id != null ? id : "UNKNOWN");
    }

    public String getId()                           { return id; }
    public void   setId(String id)                  { this.id = id; }
    public String getFirstName()                    { return firstName; }
    public void   setFirstName(String fn)           { this.firstName = fn != null ? fn.trim() : null; }
    public String getLastName()                     { return lastName; }
    public void   setLastName(String ln)            { this.lastName = ln != null ? ln.trim() : null; }
    public String getGender()                       { return gender; }
    public void   setGender(String g)               { this.gender = normalizeGender(g); }
    public String getSpouseRef()                    { return spouseRef; }
    public void   setSpouseRef(String r)            { this.spouseRef = r; }
    public String getSpouseName()                   { return spouseName; }
    public void   setSpouseName(String n)           { this.spouseName = n != null ? n.trim() : null; }
    public Set<String> getParentRefs()              { return parentRefs; }
    public String getFatherName()                   { return fatherName; }
    public void   setFatherName(String n)           { this.fatherName = n != null ? n.trim() : null; }
    public String getMotherName()                   { return motherName; }
    public void   setMotherName(String n)           { this.motherName = n != null ? n.trim() : null; }
    public Set<String> getSonRefs()                 { return sonRefs; }
    public Set<String> getDaughterRefs()            { return daughterRefs; }
    public Set<String> getChildNames()              { return childNames; }
    public int  getDeclaredChildrenCount()          { return declaredChildrenCount; }
    public void setDeclaredChildrenCount(int n)     { this.declaredChildrenCount = n; }
    public Set<String> getSiblingRefs()             { return siblingRefs; }
    public Set<String> getBrotherNames()            { return brotherNames; }
    public Set<String> getSisterNames()             { return sisterNames; }
    public int  getDeclaredSiblingsCount()          { return declaredSiblingsCount; }
    public void setDeclaredSiblingsCount(int n)     { this.declaredSiblingsCount = n; }
    public List<String> getWarnings()               { return warnings; }

    private static String normalizeGender(String raw) {
        if (raw == null) return null;
        String s = raw.trim().toLowerCase();
        if (s.equals("m") || s.equals("male"))   return "male";
        if (s.equals("f") || s.equals("female")) return "female";
        return null;
    }
}