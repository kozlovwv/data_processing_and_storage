package ru.nsu.kozlov;

import java.io.OutputStream;
import java.util.Map;

public interface PeopleWriter {
    void write(Map<String, Person> registry, OutputStream out) throws Exception;
}