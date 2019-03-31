<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*, java.text.*" %>

<%!
String getFormattedDate(){
    SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy hh:mm:ss");
    return sdf.format(new Date());
}
%>

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Doctor App</title>
</head>
    <body>
        <h2>
            Hello WEB! <br/>
            <i>Сегодня <%= getFormattedDate() %></i>
        </h2>

        <br/>
        <a href="${pageContext.request.contextPath}/login.jsp">Login</a>
        <br>
        <a href="${pageContext.request.contextPath}/api/students">StudentList</a>
       <br>
       <a href="${pageContext.request.contextPath}/api/exception">Exception</a>
              <br>

    </body>
</html>
