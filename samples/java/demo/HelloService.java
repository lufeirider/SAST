package demo;

import java.util.List;

public class HelloService extends BaseService implements Runnable {
    private String name;
    private int count;

    public HelloService(String name) {
        this.name = name;
        this.count = 0;
    }

    public String greet(String user) {
        String msg = buildMessage(user);
        log(msg);
        count++;
        return msg;
    }

    private String buildMessage(String user) {
        return "Hello, " + user + " from " + name;
    }

    private void log(String msg) {
        System.out.println(msg);
    }

    @Override
    public void run() {
        greet("world");
    }
}
