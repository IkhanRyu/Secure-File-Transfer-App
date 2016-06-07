package net.realtoner.securityapp.thread;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public interface ThreadPool {

    void execute(Runnable runnable);
}
