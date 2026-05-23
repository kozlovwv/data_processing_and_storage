package ru.nsu.kozlov;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "people")
@XmlAccessorType(XmlAccessType.FIELD)
public class JaxbPeople {

    @XmlAttribute(name = "count")
    private int count;

    @XmlElement(name = "person")
    private List<JaxbPerson> persons = new ArrayList<>();

    public JaxbPeople() {}

    public int getCount()                        { return count; }
    public void setCount(int count)              { this.count = count; }
    public List<JaxbPerson> getPersons()         { return persons; }
    public void setPersons(List<JaxbPerson> p)   { this.persons = p; }
}