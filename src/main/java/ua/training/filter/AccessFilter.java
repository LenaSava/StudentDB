package ua.training.filter;

import ua.training.model.entity.Teacher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

//TODO: add to web.xml
public class AccessFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Teacher teacher;
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String path = request.getRequestURI();
        if(path.contains("add-student")) {//TODO: rewrite add user roles
            if ((teacher = (Teacher) ((HttpServletRequest) servletRequest).getSession().getAttribute("teacher")) != null) {
                filterChain.doFilter(servletRequest,servletResponse);
            }else{
                servletResponse.getWriter().append("AccessDenied");
                return;
            }
        }else{
                filterChain.doFilter(servletRequest,servletResponse);
        }
    }

    @Override
    public void destroy() {

    }
}
