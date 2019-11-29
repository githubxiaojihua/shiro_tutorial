package com.xiaojihua.shiro;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Tutorial {
    private static final transient Logger log = LoggerFactory.getLogger(Tutorial.class);

    public static void main(String[] args){
        log.info("My First Apache Shiro Application");
        //启用shiro，使用ini文件中的数据进行初始化，ini里面有用户名称和角色与权限
        //1
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //2
        SecurityManager manager = factory.getInstance();
        //3
        SecurityUtils.setSecurityManager(manager);

        //获得当前用户，未登录的情况下是匿名用户
        Subject current = SecurityUtils.getSubject();
        //
        Session session = current.getSession();
        session.setAttribute("somekey","avalue");
        String value = (String)session.getAttribute("somekey");
        if(value.equals("avalue")){
            log.info("current value:" + value);
        }

        //登录用户并检查
        if(!current.isAuthenticated()){
            //根据用户名和密码形成token
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr","vespa");
            //支持 rememberMe
            token.setRememberMe(true);
            try{
                //登陆，如果出现错误比如用户名不存在啥的根据抛出的异常进行提示
                current.login(token);
            } catch (UnknownAccountException uae) {
                log.info("There is no user with username of " + token.getPrincipal());
            } catch(IncorrectCredentialsException ice) {
                log.info("Password for account " + token.getPrincipal() + " was incorrect!");
            } catch(LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked. " +
                        "Please contact your administrator to unlock it.");
            }
            // … catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) {
                //unexpected condition? error?
            }
        }

        //获得当前登陆的用户
        log.info("User[" + current.getPrincipal() + "] logged in successfully");

        //判断是否具有某个角色
        if(current.hasRole("schwartz")){
            log.info("May the Schwartz be with you!");
        }else{
            log.info("Hello, mere mortal.");
        }


        //test a typed permission (not instance-level)
        if (current.isPermitted("lightsaber:weild")) {
            log.info("You may use a lightsaber ring. Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        if (current.isPermitted("winnebago:drive:eagle5")) {
            log.info("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5' . " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!
        current.logout();
        System.exit(0);
    }
}
