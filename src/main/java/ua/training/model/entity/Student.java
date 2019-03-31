package ua.training.model.entity;

import java.util.ArrayList;
import java.util.List;

public class Student {
    private int id;
    private String name;
    private int groupe;

    List<Teacher> teachers = new ArrayList<>();

    public Student() {
    }
    public Student(int id, String name, int groupe,
                   List<Teacher> teachers) {
        this.id = id;
        this.name = name;
        this.groupe = groupe;
        this.teachers = teachers;
    }

    public int getId() {
        return id;
    }
    public void setId(int id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public int getGroupe() {
        return groupe;
    }
    public void setGroupe(int groupe) {
        this.groupe = groupe;
    }
    public List<Teacher> getTeachers() {
        return teachers;
    }
    public void setTeachers(List<Teacher> teachers) {
        this.teachers = teachers;
    }

    @Override
    public String toString() {
        return "Student{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", groupe=" + groupe +
                //", teachers=" + teachers +
                '}';
    }
}
