#include <csignal>

namespace TermSignal{

    static volatile bool keepRunning = false;

    void sig_handler(int sig){

        if ( sig == SIGINT)
        {
            keepRunning = false;
        }
    };
    void init(){
        keepRunning = true;
        signal( SIGINT, sig_handler );
    }

    bool ok(){
        return keepRunning;
    }

}

