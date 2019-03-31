package ua.training.model.dao.impl;

import ua.training.model.dao.DaoFactory;
import ua.training.model.dao.StudentDao;
import ua.training.model.dao.TeacherDao;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class JDBCDaoFactory extends DaoFactory {

    private DataSource dataSource = ConnectionPoolHolder.getDataSource();

    @Override
    public TeacherDao createTeacherDao() {
        return new JDBCTeacherDao(getConnection());
    }
    @Override
    public StudentDao createStudentDao() {
        return new JDBCStudentDao(getConnection());
    }

    private Connection getConnection(){
        try {
            return dataSource.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
