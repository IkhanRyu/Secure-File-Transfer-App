package net.realtoner.securityapp.thread;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public class ConcurrentThreadPool implements ThreadPool{

    private int threadPoolSize = 5;

    private ExecutorService executorService = null;

    public ConcurrentThreadPool(){

    }

    public ConcurrentThreadPool(int threadPoolSize){
        this.threadPoolSize = threadPoolSize;
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public void setThreadPoolSize(int threadPoolSize) {
        this.threadPoolSize = threadPoolSize;
    }

    @Override
    public void execute(Runnable runnable) {

        if(executorService == null)
            executorService = Executors.newFixedThreadPool(threadPoolSize);

        executorService.execute(runnable);
    }
}
