package ua.training.model.dao.impl;

import ua.training.model.dao.StudentDao;
import ua.training.model.dao.mapper.StudentMapper;
import ua.training.model.dao.mapper.TeacherMapper;
import ua.training.model.entity.Student;
import ua.training.model.entity.Teacher;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JDBCStudentDao implements StudentDao {
    private Connection connection;


    public JDBCStudentDao(Connection connection) {
        this.connection = connection;
    }

    @Override
    public void create(Student entity) {

    }

    @Override
    public Student findById(int id) {
        return null;
    }

    @Override
    public List<Student> findAll() {
        Map<Integer, Student> students = new HashMap<>();
        Map<Integer, Teacher> teachers = new HashMap<>();

        final String query = "" +
                " select * from studen" +
                " left join studen_has_teacher using (idstuden)" +
                " left join teacher using (idteacher)";
        try (Statement st = connection.createStatement()) {
            ResultSet rs = st.executeQuery(query);

            TeacherMapper teacherMapper = new TeacherMapper();
            StudentMapper studentMapper = new StudentMapper();

            while (rs.next()) {
                Student student = studentMapper
                        .extractFromResultSet(rs);
                Teacher teacher = teacherMapper
                        .extractFromResultSet(rs);
                student = studentMapper
                        .makeUnique(students, student);
                teacher = teacherMapper
                        .makeUnique(teachers, teacher);
                student.getTeachers().add(teacher);
            }
            return new ArrayList<>(students.values());
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }



    @Override
    public void update(Student entity) {

    }

    @Override
    public void delete(int id) {

    }

    @Override
    public void close()  {
        try {
            connection.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
