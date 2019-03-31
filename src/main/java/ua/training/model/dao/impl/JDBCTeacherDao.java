package ua.training.model.dao.impl;

import ua.training.model.dao.TeacherDao;
import ua.training.model.dao.mapper.TeacherMapper;
import ua.training.model.entity.Teacher;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class JDBCTeacherDao implements TeacherDao {
    private Connection connection;

    public JDBCTeacherDao(Connection connection) {
        this.connection = connection;
    }


    @Override
    public void create(Teacher entity) {

    }

    @Override
    public Teacher findById(int id) {
        return null;
    }



    @Override
    public List<Teacher> findAll() {
        return null;
    }

    @Override
    public void update(Teacher entity) {

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

    @Override
    public Optional<Teacher> findByName(String name) {

        Optional<Teacher> result = Optional.empty();
        try(PreparedStatement ps = connection.prepareCall("SELECT * FROM teacher WHERE name = ?")){
            ps.setString( 1, name);
            ResultSet rs;
            rs = ps.executeQuery();
            TeacherMapper mapper = new TeacherMapper();
            if (rs.next()){
                result = Optional.of(mapper.extractFromResultSet(rs));
            }//TODO : ask question how avoid two teachers with the same name
        }catch (Exception ex){
            throw new RuntimeException(ex);
        }
        return result;
    }
}
